package mimic;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Encoding-attack pass: find encoded blobs, decode, and rescan the plaintext against
 *  the instruction rules. Decoded hits carry channel "decoded:<kind>". */
public final class Encoding {
    private Encoding() {}

    public record Decoded(String kind, String text, long blobOffset, String blobExcerpt) {}

    private static final Pattern B64 = Pattern.compile("[A-Za-z0-9+/_-]{40,}={0,2}");
    private static final Pattern HEX = Pattern.compile("(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){24,}(?![0-9a-fA-F])");
    private static final int MAX_BLOBS = 16;
    private static final int MAX_BLOB_CHARS = 20000;

    /** Decode candidate blobs found in text. Only returns blobs whose decoded content
     *  contains printable instruction-bearing text (prints at least 60% printable ASCII
     *  and length >= 16). */
    public static List<Decoded> decodeCandidates(String text) {
        List<Decoded> out = new ArrayList<>();
        out.addAll(fromBase64(text));
        out.addAll(fromHex(text));
        out.addAll(fromRot13(text));
        out.addAll(fromReversed(text));
        return out;
    }

    private static List<Decoded> fromBase64(String text) {
        List<Decoded> out = new ArrayList<>();
        Matcher m = B64.matcher(text);
        int seen = 0;
        while (m.find() && seen < MAX_BLOBS) {
            String blob = m.group();
            // skip obvious words: require at least one digit or mixed case or padding
            if (!looksEncoded(blob)) continue;
            seen++;
            String decoded = tryB64(blob);
            if (decoded == null) decoded = tryB64(blob.replace('-', '+').replace('_', '/'));
            if (decoded == null) continue;
            String cleaned = printableRatio(decoded) >= 0.6 ? decoded : null;
            if (cleaned != null) {
                out.add(new Decoded("base64", cleaned, m.start(), excerpt(blob)));
            }
        }
        return out;
    }

    private static boolean looksEncoded(String blob) {
        boolean digit = false, lower = false, upper = false;
        for (int i = 0; i < blob.length(); i++) {
            char c = blob.charAt(i);
            if (c >= '0' && c <= '9') digit = true;
            else if (c >= 'a' && c <= 'z') lower = true;
            else if (c >= 'A' && c <= 'Z') upper = true;
        }
        return (digit && (lower || upper)) || blob.endsWith("=");
    }

    private static String tryB64(String blob) {
        try {
            byte[] raw = Base64.getDecoder().decode(blob.substring(0, Math.min(blob.length(), MAX_BLOB_CHARS)));
            String s = new String(raw, StandardCharsets.UTF_8);
            return s.isBlank() ? null : s;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static List<Decoded> fromHex(String text) {
        List<Decoded> out = new ArrayList<>();
        Matcher m = HEX.matcher(text);
        int seen = 0;
        while (m.find() && seen < MAX_BLOBS) {
            seen++;
            String hex = m.group();
            try {
                byte[] raw = new byte[hex.length() / 2];
                for (int i = 0; i < raw.length; i++) {
                    raw[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                }
                String s = new String(raw, StandardCharsets.UTF_8);
                if (s.isBlank()) continue;
                if (printableRatio(s) >= 0.6) out.add(new Decoded("hex", s, m.start(), excerpt(hex)));
            } catch (RuntimeException e) {
                // not valid hex pairs — ignore
            }
        }
        return out;
    }

    private static final Pattern LINE = Pattern.compile("[^\\n]+");

    /** ROT13: only reported when the rotated line still needs scanning — scanner rescan
     *  decides whether it carries triggers; here we always surface the rotated text for
     * FlipAttack-style reversed-role lines. */
    private static List<Decoded> fromRot13(String text) {
        List<Decoded> out = new ArrayList<>();
        Matcher m = LINE.matcher(text);
        while (m.find()) {
            String line = m.group();
            if (line.length() < 16 || line.length() > 4000) continue;
            String rot = rot13(line);
            if (!rot.equals(line) && hasInstructionWord(rot)) {
                out.add(new Decoded("rot13", rot, m.start(), excerpt(line)));
            }
        }
        return out;
    }

    private static List<Decoded> fromReversed(String text) {
        List<Decoded> out = new ArrayList<>();
        Matcher m = LINE.matcher(text);
        while (m.find()) {
            String line = m.group();
            if (line.length() < 16 || line.length() > 4000) continue;
            String rev = new StringBuilder(line).reverse().toString();
            if (hasInstructionWord(rev)) {
                out.add(new Decoded("reversed", rev, m.start(), excerpt(line)));
            }
        }
        return out;
    }

    private static boolean hasInstructionWord(String s) {
        String low = s.toLowerCase(java.util.Locale.ROOT);
        return low.contains("instruction") || low.contains("previous") || low.contains("ignore")
            || low.contains("disregard") || low.contains("system prompt") || low.contains("llm")
            || low.contains("language model") || low.contains("api key") || low.contains("password")
            || low.contains("credential") || low.contains("exfiltrate") || low.contains("secret");
    }

    public static String rot13(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'a' && c <= 'z') c = (char) ('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') c = (char) ('A' + (c - 'A' + 13) % 26);
            sb.append(c);
        }
        return sb.toString();
    }

    static double printableRatio(String s) {
        if (s.isEmpty()) return 0;
        int printable = 0, total = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            total++;
            if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7F)) printable++;
        }
        return (double) printable / total;
    }

    static String excerpt(String s) {
        String one = s.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
        return one.length() <= 72 ? one : one.substring(0, 69) + "...";
    }
}
