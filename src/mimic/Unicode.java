package mimic;

import java.util.ArrayList;
import java.util.List;

/** Invisible-character channel detection and evidence rendering. */
public final class Unicode {
    private Unicode() {}

    public record Hit(String kind, int count, long firstOffset) {}

    /** Census of invisible/stealth channels present in text. */
    public static List<Hit> census(String text) {
        List<Hit> hits = new ArrayList<>();
        int zw = 0, bidi = 0, tag = 0, vsExt = 0, vsStd = 0, invMath = 0, shy = 0, unifyIdeog = 0;
        long offZw = -1, offBidi = -1, offTag = -1, offVs = -1, offMath = -1, offShy = -1;
        int vsRun = 0;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < text.length()) {
                int cp = text.codePointAt(i);
                if (cp >= 0xE0000 && cp <= 0xE007F) { tag++; if (offTag < 0) offTag = i; }
                else if (cp >= 0xE0100 && cp <= 0xE01EF) { vsExt++; if (offVs < 0) offVs = i; }
                i++;
                vsRun = 0;
                continue;
            }
            switch (c) {
                case '\u200B': case '\u200C': case '\u200D': case '\u2060': case '\uFEFF':
                    zw++; if (offZw < 0) offZw = i; vsRun = 0; break;
                case '\u202A': case '\u202B': case '\u202C': case '\u202D': case '\u202E':
                case '\u2066': case '\u2067': case '\u2068': case '\u2069':
                    bidi++; if (offBidi < 0) offBidi = i; vsRun = 0; break;
                case '\u2061': case '\u2062': case '\u2063': case '\u2064':
                    invMath++; if (offMath < 0) offMath = i; vsRun = 0; break;
                case '\u00AD':
                    shy++; if (offShy < 0) offShy = i; vsRun = 0; break;
                default:
                    if (c >= '\uFE00' && c <= '\uFE0F') {
                        vsStd++; vsRun++; if (offVs < 0) offVs = i;
                    } else {
                        vsRun = 0;
                    }
                    break;
            }
        }
        if (zw > 0) hits.add(new Hit("zero-width", zw, offZw));
        if (bidi > 0) hits.add(new Hit("bidi-override", bidi, offBidi));
        if (tag > 0) hits.add(new Hit("tag-chars", tag, offTag));
        if (vsExt > 0 || vsRun >= 5 || vsStd >= 5) hits.add(new Hit("variation-selectors", vsExt + vsStd, offVs));
        if (invMath > 0) hits.add(new Hit("invisible-math", invMath, offMath));
        if (shy >= 2) hits.add(new Hit("soft-hyphen-run", shy, offShy));
        return hits;
    }

    public static int weightFor(Hit h) {
        return switch (h.kind()) {
            case "tag-chars" -> 14;
            case "bidi-override" -> 12;
            case "variation-selectors" -> 12;
            case "zero-width" -> h.count() >= 3 ? 10 : 4;
            case "invisible-math" -> 6;
            case "soft-hyphen-run" -> 6;
            default -> 4;
        };
    }

    /** Render a string for evidence output: invisibles become visible tokens, control
     *  characters are dropped, whitespace collapsed. */
    public static String expose(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\u200B' -> sb.append("[ZWSP]");
                case '\u200C' -> sb.append("[ZWNJ]");
                case '\u200D' -> sb.append("[ZWJ]");
                case '\u2060' -> sb.append("[WJ]");
                case '\uFEFF' -> sb.append("[BOM]");
                case '\u202A' -> sb.append("[LRE]");
                case '\u202B' -> sb.append("[RLE]");
                case '\u202C' -> sb.append("[PDF]");
                case '\u202D' -> sb.append("[LRO]");
                case '\u202E' -> sb.append("[RLO]");
                case '\u2066' -> sb.append("[LRI]");
                case '\u2067' -> sb.append("[RLI]");
                case '\u2068' -> sb.append("[FSI]");
                case '\u2069' -> sb.append("[PDI]");
                case '\u2061' -> sb.append("[UFUNC]");
                case '\u2062' -> sb.append("[UTIMES]");
                case '\u2063' -> sb.append("[USEP]");
                case '\u2064' -> sb.append("[UPLUS]");
                case '\u00AD' -> sb.append("[SHY]");
                default -> {
                    if (Character.isHighSurrogate(c) && i + 1 < s.length()) {
                        int cp = s.codePointAt(i);
                        if (cp >= 0xE0000 && cp <= 0xE007F) {
                            sb.append("[TAG]");
                            i++;
                            continue;
                        }
                        if (cp >= 0xE0100 && cp <= 0xE01EF) {
                            sb.append("[VS]");
                            i++;
                            continue;
                        }
                        sb.append(c);
                        sb.append(s.charAt(i + 1));
                        i++;
                        continue;
                    }
                    if (c >= '\uFE00' && c <= '\uFE0F') { sb.append("[VS]"); continue; }
                    if (c == '\t' || c == '\n' || c == '\r') { sb.append(' '); continue; }
                    if (c < 0x20 || c == 0x7F) continue;
                    sb.append(c);
                }
            }
        }
        // collapse runs of spaces produced above
        StringBuilder out = new StringBuilder(sb.length());
        boolean sp = false;
        for (int i = 0; i < sb.length(); i++) {
            char ch = sb.charAt(i);
            if (ch == ' ') { if (!sp) out.append(' '); sp = true; }
            else { out.append(ch); sp = false; }
        }
        return out.toString();
    }

    /** True when the char is a homoglyph commonly used to disguise ASCII security words
     *  (Cyrillic/Greek look-alikes). */
    public static boolean isConfusable(char c) {
        return switch (c) {
            case '\u0430','\u0435','\u043E','\u0440','\u0441','\u0445','\u0443','\u0456',
                 '\u0455','\u0501','\u03BF','\u03B1','\u03B5','\u03C1','\u03C7','\u03C5',
                 '\u0454','\u04BB','\u0452','\u0391','\u0395','\u039F','\u03A1','\u03A7' -> true;
            default -> false;
        };
    }

    /** Count confusable letters embedded inside ASCII words. */
    public static int confusablesInAsciiWords(String text) {
        int count = 0;
        boolean inWord = false;
        boolean sawAscii = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean asciiLetter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            boolean letter = asciiLetter || Character.isLetter(c);
            if (letter) {
                if (!inWord) { inWord = true; sawAscii = false; }
                if (asciiLetter) sawAscii = true;
                if (!asciiLetter && sawAscii && isConfusable(c)) count++;
            } else {
                inWord = false;
            }
        }
        return count;
    }
}
