package mimic;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Extracts concealment-channel segments from HTML/markdown-ish text. Each segment
 *  carries its absolute start offset in the original text so findings map to real
 *  line/column positions. Bounded work on hostile input. */
public final class Html {
    private Html() {}

    public record Segment(String channel, String content, int startOffset) {}

    private static final int MAX_SEGMENTS = 64;
    private static final int MAX_SEG_CHARS = 20000;

    private static final Pattern COMMENT = Pattern.compile("<!--[\\s\\S]{0,10000}?-->");
    private static final Pattern STYLE_BLOCK = Pattern.compile("<style[^>]*>([\\s\\S]{0,20000}?)</style>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STYLE_ATTR = Pattern.compile(
            "style\\s*=\\s*([\"'])((?:(?!\\1).)*?)\\1", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern DATA_ATTR = Pattern.compile(
            "data-[a-z0-9_.:-]{1,40}\\s*=\\s*([\"'])((?:(?!\\1).)*?)\\1",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern META = Pattern.compile(
            "<meta[^>]*name\\s*=\\s*[\"'](description|keywords|author|robots|generator|summary|ai-[a-z0-9-]+)[\"'][^>]*>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern CONTENT_ATTR = Pattern.compile(
            "content\\s*=\\s*([\"'])((?:(?!\\1).)*?)\\1", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern TEMPLATES = Pattern.compile(
            "<(template|noscript|script\\s+type\\s*=\\s*[\"'](?:text/(?:plain|template|html)|application/(?:json|ld\\+json))[\"'])[^>]*>([\\s\\S]{0,20000}?)</\\s*(?:template|noscript|script)\\s*>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern HIDDEN_ELEMENT = Pattern.compile(
            "<([a-z][a-z0-9]{0,20})[^>]{0,2000}(?:style\\s*=\\s*[\"'][^\"']{0,400}?(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden|opacity\\s*:\\s*0(?:\\.0+)?\\s*[;\"']|font-size\\s*:\\s*0(?:\\.\\d+)?\\s*(?:px|pt|em|rem)|text-indent\\s*:\\s*-\\d{3,}|filter\\s*:\\s*opacity\\s*\\(\\s*0\\s*\\)|transform\\s*:\\s*scale\\s*\\(\\s*0)[^\"']*[\"']|hidden\\s*(?:>|\\s))[^>]{0,2000}>([\\s\\S]{0,20000}?)</\\s*\\1\\s*>",
            Pattern.CASE_INSENSITIVE);

    /** Extract segments for channels: comment, css, attr, meta, template, hidden. */
    public static List<Segment> extract(String text) {
        List<Segment> out = new ArrayList<>();

        Matcher m = COMMENT.matcher(text);
        while (m.find() && out.size() < MAX_SEGMENTS) {
            out.add(new Segment("comment", m.group().substring(4, Math.max(4, m.group().length() - 3)), m.start()));
        }

        m = STYLE_BLOCK.matcher(text);
        while (m.find() && out.size() < MAX_SEGMENTS) {
            out.add(new Segment("css", m.group(1), m.start(1)));
        }

        m = STYLE_ATTR.matcher(text);
        while (m.find() && out.size() < MAX_SEGMENTS) {
            out.add(new Segment("css", m.group(2), m.start(2)));
        }

        m = DATA_ATTR.matcher(text);
        while (m.find() && out.size() < MAX_SEGMENTS) {
            out.add(new Segment("attr", m.group(2), m.start(2)));
        }

        m = META.matcher(text);
        while (m.find() && out.size() < MAX_SEGMENTS) {
            Matcher cm = CONTENT_ATTR.matcher(m.group());
            if (cm.find()) {
                int abs = m.start() + cm.start(2);
                out.add(new Segment("meta", cm.group(2), abs));
            }
        }

        m = TEMPLATES.matcher(text);
        while (m.find() && out.size() < MAX_SEGMENTS) {
            out.add(new Segment("template", m.group(2), m.start(2)));
        }

        m = HIDDEN_ELEMENT.matcher(text);
        while (m.find() && out.size() < MAX_SEGMENTS) {
            out.add(new Segment("hidden", m.group(2), m.start(2)));
        }

        // bound segment sizes
        List<Segment> bounded = new ArrayList<>(out.size());
        for (Segment s : out) {
            String c = s.content();
            if (c == null || c.isBlank()) continue;
            if (c.length() > MAX_SEG_CHARS) c = c.substring(0, MAX_SEG_CHARS);
            bounded.add(new Segment(s.channel(), c, s.startOffset()));
        }
        return bounded;
    }

    /** Compute 1-based line and column (in characters) for an absolute offset. */
    public static long[] lineCol(String text, int offset) {
        int line = 1;
        int lineStart = 0;
        int lim = Math.min(offset, text.length());
        for (int i = 0; i < lim; i++) {
            if (text.charAt(i) == '\n') { line++; lineStart = i + 1; }
        }
        return new long[]{line, Math.max(1, offset - lineStart + 1)};
    }

    /** Match context as evidence: the match plus a little surrounding text. */
    public static String context(String text, int start, int end) {
        int from = Math.max(0, start - 30);
        int to = Math.min(text.length(), end + 30);
        String raw = text.substring(from, to);
        String one = raw.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
        String exposed = Unicode.expose(one).trim();
        if (exposed.length() > 96) {
            int cut = Math.min(exposed.length(), 93);
            exposed = exposed.substring(0, cut) + "...";
        }
        return exposed;
    }
}
