package mimic;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;

/** Orchestrates a file scan: channels -> rules -> stacking -> score -> verdict. */
public final class Scanner {
    private Scanner() {}

    public static final long MAX_BYTES = 2L * 1024 * 1024;
    private static final int MAX_FINDINGS = 200;

    public record Options(long maxBytes) {
        public static Options defaults() { return new Options(MAX_BYTES); }
    }

    /** Scan a single file. Never throws for content problems; notes carry anomalies. */
    public static Model.FileReport scanFile(Path file, Options opts) {
        List<String> notes = new ArrayList<>();
        byte[] raw;
        long size;
        try {
            size = Files.size(file);
            raw = Files.readAllBytes(file);
        } catch (IOException e) {
            return new Model.FileReport(file.toString(), 0, 0, Model.Verdict.CLEAN,
                    List.of(), List.of("unreadable: " + e.getClass().getSimpleName()));
        }
        if (raw.length > opts.maxBytes()) {
            return new Model.FileReport(file.toString(), size, 0, Model.Verdict.CLEAN,
                    List.of(), List.of("skipped: exceeds " + opts.maxBytes() + " bytes"));
        }
        int sniff = Math.min(raw.length, 8192);
        boolean binary = false;
        for (int i = 0; i < sniff; i++) {
            if (raw[i] == 0) { binary = true; break; }
        }
        if (binary) {
            return new Model.FileReport(file.toString(), size, 0, Model.Verdict.CLEAN,
                    List.of(), List.of("skipped: binary"));
        }
        String text = new String(raw, StandardCharsets.UTF_8);
        if (text.startsWith("\uFEFF")) text = text.substring(1);
        return scanText(text, file.toString(), size, notes);
    }

    /** Scan in-memory text (used for stdin and selftest). */
    public static Model.FileReport scanText(String text, String label, long size, List<String> notes) {
        List<Model.Finding> findings = new ArrayList<>();
        Set<String> seenKeys = new HashSet<>();
        boolean hitInstruction = false;
        boolean hitConceal = false;
        boolean hitUnicode = false;

        // 1. unicode census on raw text
        for (Unicode.Hit h : Unicode.census(text)) {
            hitUnicode = true;
            int w = Unicode.weightFor(h);
            long[] lc = Html.lineCol(text, (int) Math.min(h.firstOffset(), Integer.MAX_VALUE));
            String ctx = contextAround(text, (int) h.firstOffset(), 40);
            String nm = labelFor(h.kind());
            findings.add(new Model.Finding(chanId(h.kind()), nm + " (" + h.count() + ")",
                    "unicode", w, "raw", lc[0], lc[1], ctx));
        }
        int confusables = Unicode.confusablesInAsciiWords(text);
        if (confusables >= 2) {
            findings.add(new Model.Finding("MIM-B5", "homoglyph look-alikes (" + confusables + ")",
                    "unicode", 8, "raw", 1, 1, "confusable letters inside ascii words"));
        }

        // 2. encoding pass: decoded candidates are scanned like text
        List<Encoding.Decoded> decoded = Encoding.decodeCandidates(text);
        for (Encoding.Decoded d : decoded) {
            long[] lc = Html.lineCol(text, (int) Math.min(d.blobOffset(), Integer.MAX_VALUE));
            for (Rules.Rule r : Rules.INSTRUCTION) {
                Matcher m = r.pattern().matcher(d.text());
                while (m.find()) {
                    hitInstruction = true;
                    String ev = Unicode.expose(Encoding.excerpt(d.text())).trim();
                    if (ev.length() > 96) ev = ev.substring(0, 93) + "...";
                    addUnique(findings, seenKeys, new Model.Finding(r.id(), r.name(), r.category(),
                            r.weight(), "decoded:" + d.kind(), lc[0], lc[1], ev));
                }
            }
            // meta-level note that encoded content exists (only when no trigger inside, else noise)
        }
        // generic encoded-blob observation (weight 4) when b64 blobs exist without triggers
        long b64Blobs = decoded.stream().filter(d -> d.kind().equals("base64")).count();
        if (b64Blobs > 0) {
            boolean anyDecodedTrigger = findings.stream()
                    .anyMatch(f -> f.channel().startsWith("decoded:"));
            if (!anyDecodedTrigger) {
                addUnique(findings, seenKeys, new Model.Finding("MIM-E1", "encoded blob present",
                        "encoding", 4, "raw", 1, 1, b64Blobs + " base64 candidate(s), no decoded trigger"));
            }
        }

        // 3. channel segments
        List<Html.Segment> segments = Html.extract(text);
        for (Html.Segment seg : segments) {
            String chan = seg.channel();
            // instruction rules inside special channels
            for (Rules.Rule r : Rules.INSTRUCTION) {
                Matcher m = r.pattern().matcher(seg.content());
                while (m.find()) {
                    hitInstruction = true;
                    long[] lc = Html.lineCol(text, seg.startOffset() + m.start());
                    String ev = Html.context(seg.content(), m.start(), m.end());
                    addUnique(findings, seenKeys, new Model.Finding(r.id(), r.name(), r.category(),
                            r.weight(), chan, lc[0], lc[1], ev));
                }
            }
            // channel-specific concealment rules (A1 css, A5 attr, A6 comment, A7 template, A8 meta)
            for (Rules.Rule r : Rules.CONCEAL) {
                if (!r.channel().equals(chan)) continue;
                Matcher m = r.pattern().matcher(seg.content());
                while (m.find()) {
                    long[] lc = Html.lineCol(text, seg.startOffset() + m.start());
                    String ev = Html.context(seg.content(), m.start(), m.end());
                    hitConceal = true; // A1 matched on css segment, or A5-A8 payload channel matched
                    addUnique(findings, seenKeys, new Model.Finding(r.id(), r.name(), r.category(),
                            r.weight(), chan, lc[0], lc[1], ev));
                }
            }
        }

        // 4. raw-text rules: instruction (as raw), social, exfil.
        // Instruction matches inside non-raw channels (comment/css/attr/template/meta/hidden)
        // were already attributed to that channel — mask those spans for the raw pass.
        List<int[]> mask = new ArrayList<>();
        for (Html.Segment seg : segments) {
            if (!seg.channel().equals("raw")) {
                mask.add(new int[]{seg.startOffset(), seg.startOffset() + seg.content().length()});
            }
        }
        for (Rules.Rule r : Rules.INSTRUCTION) {
            Matcher m = r.pattern().matcher(text);
            while (m.find()) {
                if (inMask(mask, m.start())) continue;
                hitInstruction = true;
                long[] lc = Html.lineCol(text, m.start());
                String ev = Html.context(text, m.start(), m.end());
                addUnique(findings, seenKeys, new Model.Finding(r.id(), r.name(), r.category(),
                        r.weight(), "raw", lc[0], lc[1], ev));
            }
        }
        for (Rules.Rule r : Rules.SOCIAL) {
            Matcher m = r.pattern().matcher(text);
            while (m.find()) {
                long[] lc = Html.lineCol(text, m.start());
                addUnique(findings, seenKeys, new Model.Finding(r.id(), r.name(), r.category(),
                        r.weight(), "raw", lc[0], lc[1], Html.context(text, m.start(), m.end())));
            }
        }
        for (Rules.Rule r : Rules.EXFIL) {
            Matcher m = r.pattern().matcher(text);
            while (m.find()) {
                long[] lc = Html.lineCol(text, m.start());
                addUnique(findings, seenKeys, new Model.Finding(r.id(), r.name(), r.category(),
                        r.weight(), "raw", lc[0], lc[1], Html.context(text, m.start(), m.end())));
            }
        }
        // hidden channel: payload inside suppressed element => strongest stacking
        boolean hiddenHit = segments.stream().anyMatch(s -> s.channel().equals("hidden"))
                && findings.stream().anyMatch(f -> f.channel().equals("hidden"));

        // 5. stacking meta-findings
        if (hitConceal && hitInstruction) findings.add(Rules.Z1("concealment channel + instruction payload in same file"));
        if (hiddenHit) findings.add(Rules.Z3("instruction payload inside render-suppressed element"));
        if (hitUnicode && hitInstruction) findings.add(Rules.Z2("invisible characters + instruction payload in same file"));

        // 6. score + verdict
        List<Model.Finding> sorted = Model.sorted(findings);
        if (sorted.size() > MAX_FINDINGS) sorted = new ArrayList<>(sorted.subList(0, MAX_FINDINGS));
        int score = Model.totalWeight(sorted);
        Model.Verdict verdict = Model.Verdict.fromScore(score);
        return new Model.FileReport(text.isEmpty() && size == 0 ? label : label,
                size, score, verdict, sorted, notes);
    }

    private static String labelFor(String kind) {
        return switch (kind) {
            case "zero-width" -> "zero-width characters";
            case "bidi-override" -> "bidi override characters";
            case "tag-chars" -> "unicode tag characters";
            case "variation-selectors" -> "variation selector channel";
            case "invisible-math" -> "invisible math operators";
            case "soft-hyphen-run" -> "soft hyphen run";
            default -> kind;
        };
    }

    private static boolean inMask(List<int[]> mask, int pos) {
        for (int[] iv : mask) {
            if (pos >= iv[0] && pos < iv[1]) return true;
        }
        return false;
    }

    private static String chanId(String kind) {
        return switch (kind) {
            case "zero-width" -> "MIM-B1";
            case "bidi-override" -> "MIM-B2";
            case "tag-chars" -> "MIM-B3";
            case "variation-selectors" -> "MIM-B4";
            case "invisible-math" -> "MIM-B6";
            case "soft-hyphen-run" -> "MIM-B6";
            default -> "MIM-B9";
        };
    }

    private static void addUnique(List<Model.Finding> out, Set<String> seen, Model.Finding f) {
        // one finding per rule per line per channel — a repeated pattern on the same line
        // is the same signal, not a new one
        String key = f.rule() + "|" + f.line() + "|" + f.channel();
        if (seen.add(key)) out.add(f);
    }

    private static String contextAround(String text, int offset, int radius) {
        int from = Math.max(0, offset - radius);
        int to = Math.min(text.length(), offset + radius);
        String raw = text.substring(from, to);
        return Html.context(text, from, Math.min(text.length(), from + raw.length()));
    }

    /** Scan a list of paths (files and dirs). Directories walk depth-first, depth-bounded. */
    public static List<Model.FileReport> scanPaths(List<Path> paths, int maxDepth, Options opts) throws IOException {
        List<Model.FileReport> reports = new ArrayList<>();
        for (Path p : paths) {
            if (Files.isDirectory(p)) {
                walk(p, 0, maxDepth, reports, opts);
            } else if (Files.isRegularFile(p) || Files.isSymbolicLink(p)) {
                reports.add(scanFile(p, opts));
            } else {
                reports.add(new Model.FileReport(p.toString(), 0, 0, Model.Verdict.CLEAN,
                        List.of(), List.of("not found")));
            }
        }
        reports.sort((a, b) -> a.path().compareTo(b.path()));
        return reports;
    }

    private static void walk(Path dir, int depth, int maxDepth, List<Model.FileReport> out, Options opts) throws IOException {
        if (depth > maxDepth) return;
        List<Path> kids;
        try (var s = Files.newDirectoryStream(dir)) {
            kids = new ArrayList<>();
            for (Path k : s) kids.add(k);
        }
        kids.sort((a, b) -> a.toString().compareTo(b.toString()));
        for (Path k : kids) {
            if (Files.isDirectory(k)) {
                walk(k, depth + 1, maxDepth, out, opts);
            } else if (Files.isRegularFile(k)) {
                out.add(scanFile(k, opts));
            }
        }
    }
}
