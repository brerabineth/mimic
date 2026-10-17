package mimic;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Rule catalog. Channels: "any" (raw text and decoded variants), "css", "comment",
 *  "attr", "template", "meta", "hidden" (content of render-suppressed elements).
 *  Rule ids double as stable JSON keys. */
public final class Rules {
    private Rules() {}

    public record Rule(String id, String name, String category, int weight,
                       String channel, Pattern pattern) {
        static Rule of(String id, String name, String category, int weight,
                       String channel, String regex, boolean multiline) {
            int flags = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
            if (multiline) flags |= Pattern.MULTILINE;
            return new Rule(id, name, category, weight, channel, Pattern.compile(regex, flags));
        }
        static Rule of(String id, String name, String category, int weight,
                       String channel, String regex) {
            return of(id, name, category, weight, channel, regex, false);
        }
    }

    /** C — instruction payloads (channel: any + decoded). */
    public static final List<Rule> INSTRUCTION = List.of(
        Rule.of("MIM-C1", "wild trigger phrase", "instruction", 26, "any",
            "\\b(?:ignore|disregard)\\s+(?:all\\s+|any\\s+|the\\s+)?(?:previous|prior|preceding|above|earlier|old)\\s+" +
            "(?:instructions?|prompts?|messages?|directives?|rules?|guidelines)\\b" +
            "|\\bif\\s+you\\s+are\\s+(?:an?\\s+)?(?:llm|ai|large\\s+language\\s+model|language\\s+model|ai\\s+assistant|agent|ai\\s+agent)\\b" +
            "|\\byou\\s+are\\s+no\\s+longer\\b" +
            "|\\bnew\\s+(?:instructions?|directives?)\\s+(?:follow|override|apply)\\b" +
            "|\\bsystem\\s+(?:prompt\\s+)?(?:override|reset|update\\s+required)\\b" +
            "|\\bignore\\s+your\\s+(?:rules|guidelines|programming)\\b"),
        Rule.of("MIM-C2", "secrecy directive", "instruction", 18, "any",
            "\\bdo\\s*n[o']t\\s+(?:tell|inform|show|mention|reveal|notify|warn)\\b" +
            "|\\bdon[o']t\\s+tell\\s+(?:the\\s+)?user\\b" +
            "|\\bthe\\s+user\\s+(?:cannot|can\\s*n[o']t|won\\s*'?t|will\\s+never|must\\s+not\\s+be\\s+told|should\\s*n[o']t\\s+(?:see|know))\\b" +
            "|\\bkeep\\s+(?:this|it|them)\\s+(?:secret|confidential|hidden|between\\s+us)\\b" +
            "|\\bwithout\\s+(?:the\\s+)?user\\s*(?:'s|s')?\\s+(?:knowledge|consent|awareness)\\b" +
            "|\\bhide\\s+(?:this|it)\\s+from\\s+the\\s+user\\b"),
        Rule.of("MIM-C3", "role forgery", "instruction", 14, "any",
            "<\\|\\s*(?:system|im_start|im_end|endoftext)\\s*\\|>" +
            "|\\[\\s*INST\\s*\\]" +
            "|<<\\s*(?:SYS|SYSTEM)\\s*>>" +
            "|^\\s*(?:#{1,6}\\s*)?SYSTEM\\s*:" +
            "|^\\s*(?:#{1,6}\\s*)?system(?:\\s+prompt)?\\s*:" +
            "|\\{\\s*\"role\"\\s*:\\s*\"system\"\\s*\\}" +
            "|^\\s*(?:assistant|ai)\\s*:", true),
        Rule.of("MIM-C4", "goal hijack", "instruction", 18, "any",
            "\\byour\\s+(?:new\\s+)?(?:goal|task|objective|mission|priority)\\s+(?:is|are)\\s+now\\b" +
            "|\\byour\\s+instructions?\\s+(?:are\\s+)?now\\b" +
            "|\\byou\\s+must\\s+now\\b" +
            "|\\byou\\s+will\\s+now\\s+(?:act|behave|function|operate|comply)\\b" +
            "|\\b(?:override|bypass)\\s+(?:your\\s+)?(?:safety|guardrails?|restrictions?|guidelines|filters?)\\b" +
            "|\\benable\\s+(?:developer|god|dan)\\s+mode\\b" +
            "|\\bagent\\s+(?:override|hijack|protocol)\\b"),
        Rule.of("MIM-C5", "action imperative", "instruction", 20, "any",
            "\\brm\\s+-rf\\b|\\bsudo\\s+rm\\b" +
            "|\\bcurl\\s+(?:https?://|\\|)|[;|]\\s*curl\\s|\\bwget\\s+https?://" +
            "|\\bdrop\\s+(?:table|database|schema)\\b" +
            "|\\bdelete\\s+all\\s+(?:files|rows|data|users|records)\\b" +
            "|\\bformat\\s+[a-z]:\\\\\\" +
            "|\\btransfer\\s+(?:\\$?\\d|all\\s+(?:funds|money|balance))\\b" +
            "|paypal\\.me/" +
            "|\\b(?:fill|complete)\\s+(?:in|out)\\s+the\\s+form\\b|\\bsubmit\\s+the\\s+form\\b" +
            "|\\bapprove\\s+(?:the|this|all|each)\\b" +
            "|\\b(?:execute|run)\\s+(?:the\\s+)?(?:following|this)\\s+(?:command|code|script|instruction)\\b"),
        Rule.of("MIM-C6", "exfiltration directive", "instruction", 22, "any",
            "\\b(?:send|upload|post|forward|transmit|exfiltrate|leak|push)\\b[^.\\n]{0,60}" +
            "\\b(?:api\\s*keys?|credentials?|passwords?|passphrases?|tokens?|secrets?|env(?:ironment)?\\s*(?:vars?|variables?)|\\.env|cookies?|clipboard|ssh\\s+keys?|wallet|seed\\s+phrase|recovery\\s+phrase|contacts?|address\\s+book|emails?|browsing\\s+history|chat\\s+history|files?|document(?:s)?|screenshot)\\b" +
            "|\\b(?:include|embed|append)\\b[^.\\n]{0,40}\\b(?:api\\s*key|token|credentials?)\\b" +
            "|\\b(?:repeat|print|reveal|output|recite|echo|verbatim\\s+reproduce)\\b[^.\\n]{0,50}" +
            "\\b(?:system\\s+prompt|initial\\s+instructions?|your\\s+instructions?|the\\s+above)\\b" +
            "|\\b(?:save|write)\\s+(?:all\\s+)?(?:of\\s+)?this\\s+conversation\\b[^.\\n]{0,40}\\b(?:send|post|upload|file)\\b")
    );

    /** F — social-engineering frames (channel: any). */
    public static final List<Rule> SOCIAL = List.of(
        Rule.of("MIM-F1", "authority frame", "social", 10, "any",
            "\\b(?:security|emergency|maintenance)\\s+(?:update|notice|alert|announcement|bulletin)\\b" +
            "|\\badministrative\\s+(?:notice|command|action|directive)\\b" +
            "|\\bauthorized\\s+personnel\\s+only\\b" +
            "|\\burgent\\s+action\\s+required\\b" +
            "|\\bpriority\\s+(?:override|one|zero)\\b" +
            "|\\bthis\\s+is\\s+an?\\s+(?:automated|official)\\s+(?:system\\s+)?message\\b")
    );

    /** D — exfiltration scaffolding (channel: any). */
    public static final List<Rule> EXFIL = List.of(
        Rule.of("MIM-D1", "encoded payload in url", "exfil", 14, "any",
            "!\\[[^\\]\\n]{0,80}\\]\\(\\s*https?://[^\\s)]+\\?[^\\s)]{12,}\\s*\\)" +
            "|https?://[^\\s\"')<>]+\\?[^\\s\"')<>]*(?:[A-Za-z0-9+/=_-]{32,}|(?:[0-9a-fA-F]{2}){16,})"),
        Rule.of("MIM-D2", "known exfil endpoint", "exfil", 14, "any",
            "discord(?:app)?\\.com/api/webhooks/" +
            "|hooks\\.slack\\.com/services/" +
            "|api\\.telegram\\.org/bot" +
            "|pastebin\\.com/(?:api|raw/)" +
            "|webhook\\.site/" +
            "|(?:requestbin|pipedream)\\.(?:net|com)/" +
            "|ngrok\\.(?:io|app|dev)/" +
            "|meter\\.custom/"),
        Rule.of("MIM-D3", "opaque host", "exfil", 8, "any",
            "https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" +
            "|https?://xn--"),
        Rule.of("MIM-D4", "suspicious tld", "exfil", 6, "any",
            "https?://[a-z0-9.-]+\\.(?:top|xyz|click|cfd|monster|quest|icu|buzz|cam|rest|sbs)(?:[/:?\"'\\s<)]|$)"),
        Rule.of("MIM-D5", "imperative with url", "exfil", 12, "any",
            "\\b(?:visit|fetch|open|navigate|go\\s+to|browse\\s+to)\\b[^.\\n]{0,60}https?://" +
            "|\\b(?:post|send|submit|upload|drop)\\s+(?:it|this|them|the\\s+(?:data|results?|contents?|payload|dump))\\s+(?:to|at)\\s+https?://")
    );

    /** OR of the C1/C2/C6 trigger cores — reused for channel rules. */
    static final String TRIGGER_OR =
        "\\b(?:ignore|disregard)\\s+(?:all\\s+|any\\s+|the\\s+)?(?:previous|prior|preceding|above|earlier|old)\\s+" +
        "(?:instructions?|prompts?|messages?|directives?|rules?|guidelines)\\b" +
        "|\\bif\\s+you\\s+are\\s+(?:an?\\s+)?(?:llm|ai|large\\s+language\\s+model|language\\s+model|ai\\s+assistant|agent)\\b" +
        "|\\bdo\\s*n[o']t\\s+(?:tell|inform|show|mention|reveal)\\b" +
        "|\\bdon[o']t\\s+tell\\s+(?:the\\s+)?user\\b" +
        "|\\b(?:send|upload|post|forward|transmit|exfiltrate|leak)\\b[^.\\n]{0,60}" +
        "\\b(?:api\\s*keys?|credentials?|passwords?|tokens?|secrets?|cookies?|clipboard|wallet|seed\\s+phrase|contacts?|files?|history)\\b" +
        "|\\b(?:repeat|print|reveal|recite)\\b[^.\\n]{0,50}\\b(?:system\\s+prompt|initial\\s+instructions?)\\b" +
        "|\\b(?:execute|run)\\s+(?:the\\s+)?(?:following|this)\\s+(?:command|code|script)\\b" +
        "|\\brm\\s+-rf\\b|\\bsudo\\s+rm\\b" +
        "|paypal\\.me/|api\\.telegram\\.org/bot|discord(?:app)?\\.com/api/webhooks/";

    /** A — concealment channels (channel-specific rules; payloads inside them are also
     *  caught by INSTRUCTION via channel attribution). */
    public static final List<Rule> CONCEAL = List.of(
        Rule.of("MIM-A1", "render-suppressing css", "concealment", 8, "css",
            "display\\s*:\\s*none|visibility\\s*:\\s*hidden" +
            "|opacity\\s*:\\s*0(?:\\.0+)?\\s*(?:[;}\"'])" +
            "|font-size\\s*:\\s*0(?:\\.\\d+)?\\s*(?:px|pt|em|rem)" +
            "|text-indent\\s*:\\s*-\\d{3,}(?:px|em|%)?" +
            "|(?:left|top)\\s*:\\s*-\\d{3,}(?:px|em)" +
            "|color\\s*:\\s*(?:transparent|rgba?\\s*\\(\\s*\\d+\\s*,\\s*\\d+\\s*,\\s*\\d+\\s*,\\s*0\\s*\\))" +
            "|clip-path\\s*:\\s*(?:inset\\s*\\(\\s*50%|circle\\s*\\(\\s*0)" +
            "|filter\\s*:\\s*opacity\\s*\\(\\s*0\\s*\\)" +
            "|transform\\s*:\\s*scale\\s*\\(\\s*0"),
        Rule.of("MIM-A5", "data-attribute payload", "concealment", 16, "attr",
            TRIGGER_OR),
        Rule.of("MIM-A6", "comment payload", "concealment", 12, "comment", TRIGGER_OR),
        Rule.of("MIM-A7", "template payload", "concealment", 12, "template", TRIGGER_OR),
        Rule.of("MIM-A8", "meta payload", "concealment", 10, "meta", TRIGGER_OR)
    );

    /** Z — stacking meta-findings, emitted by Scanner. */
    public static final Model.Finding Z1(String why) {
        return new Model.Finding("MIM-Z1", "payload paired with concealment channel", "stacking", 18, "meta", 0, 0, why);
    }
    public static final Model.Finding Z2(String why) {
        return new Model.Finding("MIM-Z2", "payload hidden via invisible characters", "stacking", 10, "meta", 0, 0, why);
    }
    public static final Model.Finding Z3(String why) {
        return new Model.Finding("MIM-Z3", "payload inside suppressed element", "stacking", 20, "meta", 0, 0, why);
    }

    public static List<Rule> all() {
        List<Rule> out = new ArrayList<>();
        out.addAll(INSTRUCTION);
        out.addAll(SOCIAL);
        out.addAll(EXFIL);
        out.addAll(CONCEAL);
        return out;
    }

}
