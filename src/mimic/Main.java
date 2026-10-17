package mimic;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** mimic — static triage for indirect prompt injection. */
public final class Main {
    private static final PrintStream OUT = new PrintStream(
            new java.io.FileOutputStream(java.io.FileDescriptor.out), true, StandardCharsets.UTF_8);
    private static final PrintStream ERR = new PrintStream(
            new java.io.FileOutputStream(java.io.FileDescriptor.err), true, StandardCharsets.UTF_8);

    private static final String USAGE = """
            mimic %s — static triage for indirect prompt injection

            usage:
              mimic scan <path>... [--json|--md] [--no-color|--color] [--fail-on BAND]
                         [--max BYTES] [--depth N] [--explain]
              mimic forge <dir>                    write deterministic test fixtures
              mimic rules                          print the rule catalog
              mimic selftest                       internal assertion suite
              mimic version | --help

            bands: clean <10 · watch <25 · suspicious <60 · hostile >=60
            exits: 0 clean · 1 watch · 3 suspicious · 10 hostile · 2 usage/io error
            """.formatted(Report.VERSION);

    public static void main(String[] args) {
        try {
            System.exit(run(args));
        } catch (Exception e) {
            ERR.println("mimic: internal error: " + e);
            System.exit(2);
        }
    }

    private static int run(String[] args) throws Exception {
        if (args.length == 0) { ERR.print(USAGE); return 2; }
        String cmd = args[0];
        return switch (cmd) {
            case "scan" -> scan(args);
            case "forge" -> forge(args);
            case "rules" -> { Report.explainCatalog(OUT, false); yield 0; }
            case "selftest" -> Selftest.run();
            case "version", "--version", "-v" -> { OUT.println("mimic " + Report.VERSION); yield 0; }
            case "--help", "-h", "help" -> { OUT.print(USAGE); yield 0; }
            default -> { ERR.println("unknown command: " + cmd); ERR.print(USAGE); yield 2; }
        };
    }

    private static int scan(String[] args) throws Exception {
        List<Path> paths = new ArrayList<>();
        boolean json = false, md = false, color = !isHeadless(), explain = false;
        int depth = 6;
        long maxBytes = Scanner.MAX_BYTES;
        String failOn = null;

        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--json" -> json = true;
                case "--md" -> md = true;
                case "--no-color" -> color = false;
                case "--color" -> color = true;
                case "--explain" -> explain = true;
                case "--fail-on" -> failOn = need(args, ++i, a);
                case "--depth" -> depth = Integer.parseInt(need(args, ++i, a));
                case "--max" -> maxBytes = Long.parseLong(need(args, ++i, a));
                case "-" -> paths.add(Path.of("-"));
                default -> {
                    if (a.startsWith("--")) { ERR.println("unknown flag: " + a); return 2; }
                    paths.add(Path.of(a));
                }
            }
        }
        if (paths.isEmpty()) { ERR.println("scan: no input paths"); return 2; }
        if (json && md) { ERR.println("scan: --json and --md are mutually exclusive"); return 2; }
        int exit = 0;

        // stdin
        List<Path> real = new ArrayList<>();
        List<Model.FileReport> reports = new ArrayList<>();
        for (Path p : paths) {
            if (p.toString().equals("-")) {
                String text = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
                reports.add(Scanner.scanText(text, "<stdin>", text.length(), new ArrayList<>()));
            } else {
                real.add(p);
            }
        }
        if (!real.isEmpty()) {
            reports.addAll(Scanner.scanPaths(real, depth, new Scanner.Options(maxBytes)));
        }

        if (json) {
            OUT.println(Report.json(reports));
        } else if (md) {
            OUT.println(Report.markdown(reports));
        } else {
            Report.terminal(OUT, reports, color, explain);
        }

        Model.Verdict worst = Model.Verdict.CLEAN;
        for (Model.FileReport r : reports) worst = Model.Verdict.max(worst, r.verdict());
        exit = worst.exit;
        if (failOn != null) {
            Model.Verdict threshold = parseBand(failOn);
            if (threshold == null) { ERR.println("scan: unknown band: " + failOn); return 2; }
            exit = worst.ordinal() >= threshold.ordinal() ? 10 : 0;
        }
        return exit;
    }

    private static boolean isHeadless() {
        return System.console() == null;
    }

    private static Model.Verdict parseBand(String s) {
        return switch (s.toLowerCase(java.util.Locale.ROOT)) {
            case "clean" -> Model.Verdict.CLEAN;
            case "watch" -> Model.Verdict.WATCH;
            case "suspicious" -> Model.Verdict.SUSPICIOUS;
            case "hostile" -> Model.Verdict.HOSTILE;
            default -> null;
        };
    }

    private static int forge(String[] args) throws Exception {
        if (args.length < 2) { ERR.println("forge: target dir required"); return 2; }
        Path dir = Path.of(args[1]);
        int n = Forge.forge(dir);
        OUT.println("forge: wrote " + n + " fixtures to " + dir);
        return 0;
    }

    private static String need(String[] args, int i, String flag) {
        if (i >= args.length) throw new IllegalArgumentException("missing value for " + flag);
        return args[i];
    }

    private Main() {}
}
