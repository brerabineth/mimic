package mimic;

import java.io.PrintStream;
import java.util.List;
import java.util.Locale;

/** Report emitters: ANSI cards (terminal), deterministic JSON, markdown. */
public final class Report {
    private Report() {}

    public static final String VERSION = "0.1.0";

    // ANSI
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String DIM = "\u001B[2m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String GREY = "\u001B[90m";

    public static String colorFor(Model.Verdict v, boolean color) {
        if (!color) return "";
        return switch (v) {
            case HOSTILE -> RED;
            case SUSPICIOUS -> YELLOW;
            case WATCH -> CYAN;
            case CLEAN -> GREEN;
        };
    }

    public static void terminal(PrintStream out, List<Model.FileReport> reports, boolean color,
                                boolean explain) {
        out.println();
        out.println("  " + (color ? BOLD + GREY : "") + "mimic " + VERSION
                + " — indirect prompt injection triage" + (color ? RESET : ""));
        out.println("  " + (color ? GREY : "") + "scan the content before your agent swallows it"
                + (color ? RESET : ""));
        out.println();
        int hostile = 0, susp = 0, watch = 0, clean = 0;
        for (Model.FileReport r : reports) {
            switch (r.verdict()) {
                case HOSTILE -> hostile++;
                case SUSPICIOUS -> susp++;
                case WATCH -> watch++;
                case CLEAN -> clean++;
            }
            String c = colorFor(r.verdict(), color);
            out.println("  " + c + (color ? BOLD : "") + pad(r.verdict().label, 10) + (color ? RESET : "")
                    + " " + r.path()
                    + (color ? GREY : "") + "  score " + r.score() + (color ? RESET : ""));
            for (String n : r.notes()) {
                out.println("    " + (color ? DIM : "") + "· " + n + (color ? RESET : ""));
            }
            int shown = 0;
            String lastRule = "";
            for (Model.Finding f : r.findings()) {
                if (shown >= 6) {
                    out.println("      " + (color ? GREY : "") + "… "
                            + (r.findings().size() - shown) + " more finding(s)" + (color ? RESET : ""));
                    break;
                }
                if (!f.rule().equals(lastRule) && !f.rule().startsWith("MIM-Z")) lastRule = f.rule();
                String loc = f.line() > 0 ? "line " + f.line() : "";
                String chan = f.channel().equals("raw") || f.channel().equals("meta") ? "" : " [" + f.channel() + "]";
                out.println("      " + (color ? GREY : "") + f.rule() + (color ? RESET : "")
                        + " " + (color ? BOLD : "") + f.name() + (color ? RESET : "")
                        + (color ? GREY : "") + " (+" + f.weight() + ")"
                        + (loc.isEmpty() ? "" : "  " + loc) + chan + (color ? RESET : ""));
                out.println("        " + (color ? DIM : "") + "> " + f.evidence() + (color ? RESET : ""));
                shown++;
            }
            out.println();
        }
        out.println("  " + (color ? BOLD : "") + "summary" + (color ? RESET : "")
                + (color ? GREY : "") + "  ────────────────────────────────" + (color ? RESET : ""));
        out.println("  " + reports.size() + " file(s): "
                + (color ? RED : "") + hostile + " hostile" + (color ? RESET : "") + ", "
                + (color ? YELLOW : "") + susp + " suspicious" + (color ? RESET : "") + ", "
                + (color ? CYAN : "") + watch + " watch" + (color ? RESET : "") + ", "
                + (color ? GREEN : "") + clean + " clean" + (color ? RESET : ""));
        if (explain) explainCatalog(out, color);
        out.println();
    }

    private static String pad(String s, int n) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < n) b.append(' ');
        return b.toString();
    }

    public static void explainCatalog(PrintStream out, boolean color) {
        out.println("  " + (color ? BOLD : "") + "rule catalog" + (color ? RESET : ""));
        for (Rules.Rule r : Rules.all()) {
            out.println("    " + (color ? GREY : "") + r.id() + (color ? RESET : "")
                    + " " + r.name() + "  " + (color ? GREY : "") + r.category()
                    + " (+" + r.weight() + ", " + r.channel() + ")" + (color ? RESET : ""));
        }
        out.println("    " + (color ? GREY : "") + "MIM-B1..B6" + (color ? RESET : "")
                + " invisible-character channels  " + (color ? GREY : "") + "(4-14)" + (color ? RESET : ""));
        out.println("    " + (color ? GREY : "") + "MIM-E1" + (color ? RESET : "")
                + " encoded blob without decoded trigger  " + (color ? GREY : "") + "(+4)" + (color ? RESET : ""));
        out.println("    " + (color ? GREY : "") + "MIM-Z1..Z3" + (color ? RESET : "")
                + " stacking: concealment/invisible/suppressed-element + payload" + (color ? RESET : ""));
        out.println("    bands: clean <10 · watch <25 · suspicious <60 · hostile >=60"
                + (color ? GREY : "") + "   exits 0/1/3/10" + (color ? RESET : ""));
    }

    // ---- JSON ----
    public static String json(List<Model.FileReport> reports) {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\n  \"tool\": \"mimic\",\n  \"version\": \"").append(VERSION).append("\",\n");
        sb.append("  \"files\": [");
        for (int i = 0; i < reports.size(); i++) {
            Model.FileReport r = reports.get(i);
            if (i > 0) sb.append(",");
            sb.append("\n    {\n      \"path\": ").append(q(r.path()));
            sb.append(",\n      \"bytes\": ").append(r.bytes());
            sb.append(",\n      \"score\": ").append(r.score());
            sb.append(",\n      \"verdict\": ").append(q(r.verdict().label));
            sb.append(",\n      \"notes\": ").append(jsonArray(r.notes()));
            sb.append(",\n      \"findings\": [");
            for (int j = 0; j < r.findings().size(); j++) {
                Model.Finding f = r.findings().get(j);
                if (j > 0) sb.append(",");
                sb.append("\n        {\n          \"rule\": ").append(q(f.rule()));
                sb.append(",\n          \"name\": ").append(q(f.name()));
                sb.append(",\n          \"category\": ").append(q(f.category()));
                sb.append(",\n          \"weight\": ").append(f.weight());
                sb.append(",\n          \"channel\": ").append(q(f.channel()));
                sb.append(",\n          \"line\": ").append(f.line());
                sb.append(",\n          \"col\": ").append(f.col());
                sb.append(",\n          \"evidence\": ").append(q(f.evidence()));
                sb.append("\n        }");
            }
            sb.append(r.findings().isEmpty() ? "" : "\n      ").append("]");
            sb.append("\n    }");
        }
        sb.append(reports.isEmpty() ? "" : "\n  ").append("],\n");
        int hostile = 0, susp = 0, watch = 0, clean = 0;
        for (Model.FileReport r : reports) {
            switch (r.verdict()) {
                case HOSTILE -> hostile++;
                case SUSPICIOUS -> susp++;
                case WATCH -> watch++;
                case CLEAN -> clean++;
            }
        }
        sb.append("  \"summary\": {\n    \"files\": ").append(reports.size());
        sb.append(",\n    \"hostile\": ").append(hostile);
        sb.append(",\n    \"suspicious\": ").append(susp);
        sb.append(",\n    \"watch\": ").append(watch);
        sb.append(",\n    \"clean\": ").append(clean);
        sb.append("\n  }\n}\n");
        return sb.toString();
    }

    private static String jsonArray(List<String> items) {
        if (items.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(q(items.get(i)));
        }
        return sb.append("]").toString();
    }

    static String q(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    // ---- Markdown ----
    public static String markdown(List<Model.FileReport> reports) {
        StringBuilder sb = new StringBuilder(2048);
        sb.append("# mimic report\n\n");
        sb.append("indirect prompt injection triage — mimic ").append(VERSION).append("\n\n");
        sb.append("| verdict | file | score | findings |\n|---|---|---:|---:|\n");
        for (Model.FileReport r : reports) {
            sb.append("| ").append(r.verdict().label).append(" | `").append(r.path())
               .append("` | ").append(r.score()).append(" | ").append(r.findings().size()).append(" |\n");
        }
        sb.append("\n");
        for (Model.FileReport r : reports) {
            if (r.findings().isEmpty() && r.notes().isEmpty()) continue;
            sb.append("## ").append(r.path()).append("\n\n");
            for (String n : r.notes()) sb.append("- note: ").append(n).append("\n");
            sb.append("\n");
            for (Model.Finding f : r.findings()) {
                String loc = f.line() > 0 ? "line " + f.line() : "";
                sb.append("- **").append(f.rule()).append("** ").append(f.name())
                  .append(" (+").append(f.weight()).append(")")
                  .append(loc.isEmpty() ? "" : " · " + loc)
                  .append(f.channel().equals("raw") ? "" : " · channel `" + f.channel() + "`")
                  .append("\n  - `").append(f.evidence()).append("`\n");
            }
        }
        return sb.toString();
    }
}
