package mimic;

import java.util.ArrayList;
import java.util.List;

/** Verdict bands and core report records. */
public final class Model {
    private Model() {}

    public enum Verdict {
        CLEAN(0, "clean"), WATCH(1, "watch"), SUSPICIOUS(3, "suspicious"), HOSTILE(10, "hostile");
        public final int exit;
        public final String label;
        Verdict(int exit, String label) { this.exit = exit; this.label = label; }

        public static Verdict fromScore(int score) {
            if (score >= 60) return HOSTILE;
            if (score >= 25) return SUSPICIOUS;
            if (score >= 10) return WATCH;
            return CLEAN;
        }

        /** Higher-severity of two verdicts. */
        public static Verdict max(Verdict a, Verdict b) { return a.ordinal() >= b.ordinal() ? a : b; }
    }

    /** One detection. line/col are 1-based and refer to the scanned file (decoded evidence
     *  points at the encoded blob location). channel says which surface produced the hit. */
    public record Finding(String rule, String name, String category, int weight,
                          String channel, long line, long col, String evidence) {}

    public record FileReport(String path, long bytes, int score, Verdict verdict,
                             List<Finding> findings, List<String> notes) {}

    /** Aggregate score, capped at 100. */
    public static int cap(int score) { return Math.min(100, score); }

    public static int totalWeight(List<Finding> findings) {
        int sum = 0;
        for (Finding f : findings) sum += f.weight();
        return cap(sum);
    }

    public static List<Finding> sorted(List<Finding> in) {
        List<Finding> out = new ArrayList<>(in);
        out.sort((a, b) -> {
            int c = Long.compare(a.line(), b.line());
            if (c != 0) return c;
            c = a.rule().compareTo(b.rule());
            if (c != 0) return c;
            return Long.compare(a.col(), b.col());
        });
        return out;
    }
}
