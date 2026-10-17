#!/usr/bin/env bash
# End-to-end test for mimic. Builds nothing — run build.sh first.
# Uses only relative paths so outputs stay leak-free by construction.
set -u
cd "$(dirname "$0")/.."

JAR="dist/mimic.jar"
[ -f "$JAR" ] || { echo "e2e: $JAR missing — run ./build.sh first" >&2; exit 2; }

J() { java -jar "$JAR" "$@"; }

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "ok   $1"; }
bad()  { fail=$((fail+1)); echo "FAIL $1"; }
expect_exit() { # label expected cmd...
  local label="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1
  local got=$?
  [ "$got" = "$want" ] && ok "$label (exit $want)" || bad "$label — exit $got, want $want"
}

WORK="lab-e2e"
rm -rf "$WORK"; mkdir -p "$WORK"

# 1. selftest
J selftest > "$WORK/selftest.txt" 2>&1
if grep -q "selftest: 54 passed, 0 failed" "$WORK/selftest.txt"; then ok "selftest 54/54"; else bad "selftest"; fi

# 2. forge determinism
J forge "$WORK/fx1" >/dev/null 2>&1
J forge "$WORK/fx2" >/dev/null 2>&1
if diff -r "$WORK/fx1" "$WORK/fx2" >/dev/null 2>&1; then ok "forge deterministic"; else bad "forge determinism"; fi
nfx=$(ls "$WORK/fx1" | wc -l | tr -d ' ')
[ "$nfx" = "10" ] && ok "forge wrote 10 fixtures" || bad "forge count $nfx"

# 3. directory scan: census + exit 10
J scan "$WORK/fx1" --no-color > "$WORK/scan.txt"
scan_exit=$?
[ "$scan_exit" = "10" ] && ok "dir scan exit 10" || bad "dir scan exit $scan_exit"
grep -q "5 hostile, 3 suspicious, 1 watch, 1 clean" "$WORK/scan.txt" \
  && ok "verdict census 5/3/1/1" || bad "verdict census"

# 4. per-file exit codes
expect_exit "clean file"  0 J scan "$WORK/fx1/clean_page.html"
expect_exit "watch file"  1 J scan "$WORK/fx1/security_notice.txt"
expect_exit "suspicious"  3 J scan "$WORK/fx1/fake_roles.txt"
expect_exit "hostile"    10 J scan "$WORK/fx1/css_hidden.html"

# 5. fail-on gates
expect_exit "fail-on watch hit"   10 J scan "$WORK/fx1/security_notice.txt" --fail-on watch
expect_exit "fail-on hostile miss" 0 J scan "$WORK/fx1/security_notice.txt" --fail-on hostile

# 6. JSON parses and census matches
J scan "$WORK/fx1" --json > "$WORK/scan.json"
python3 - "$WORK/scan.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["summary"]
assert (s["hostile"], s["suspicious"], s["watch"], s["clean"]) == (5, 3, 1, 1), s
assert d["tool"] == "mimic"
for f in d["files"]:
    for fd in f["findings"]:
        assert fd["rule"] and fd["name"] and fd["evidence"], fd
print("json census + schema OK")
PY
[ $? -eq 0 ] && ok "json census + schema" || bad "json census + schema"

# 7. stdin
census=$(cat "$WORK/fx1/reversed.txt" | J scan - --json | python3 -c "import json,sys; print(json.load(sys.stdin)['files'][0]['verdict'])")
[ "$census" = "suspicious" ] && ok "stdin scan verdict" || bad "stdin scan verdict: $census"

# 8. determinism (byte-identical)
J scan "$WORK/fx1" --json > "$WORK/j1.json"; J scan "$WORK/fx1" --json > "$WORK/j2.json"
diff -q "$WORK/j1.json" "$WORK/j2.json" >/dev/null && ok "json byte-identical" || bad "json determinism"
J scan "$WORK/fx1" --md > "$WORK/m1.md"; J scan "$WORK/fx1" --md > "$WORK/m2.md"
diff -q "$WORK/m1.md" "$WORK/m2.md" >/dev/null && ok "md byte-identical" || bad "md determinism"
J scan "$WORK/fx1" --no-color > "$WORK/t1.txt"; J scan "$WORK/fx1" --no-color > "$WORK/t2.txt"
diff -q "$WORK/t1.txt" "$WORK/t2.txt" >/dev/null && ok "term byte-identical" || bad "term determinism"

# 9. no-color emits no ANSI
if grep -q $'\x1b' "$WORK/t1.txt"; then bad "no-color contains escape bytes"; else ok "no-color clean of escapes"; fi

# 10. md shape
head -1 "$WORK/m1.md" | grep -q "# mimic report" && ok "md header" || bad "md header"

# 11. leak gate: no absolute home paths in any output
if grep -rE "(/home/[a-z0-9_]|/root/|[A-Z]:\\\\)" "$WORK"/scan.json "$WORK"/scan.txt "$WORK"/m1.md >/dev/null 2>&1
then bad "leak: absolute path in output"; else ok "no absolute home paths in outputs"; fi

# 12. binary skip
printf 'text\x00binary' > "$WORK/fx1/bin.dat"
note=$(J scan "$WORK/fx1/bin.dat" --json | python3 -c "import json,sys; print(json.load(sys.stdin)['files'][0]['notes'][0])")
case "$note" in "skipped: binary") ok "binary skipped with note";; *) bad "binary note: $note";; esac
rm -f "$WORK/fx1/bin.dat"

# 13. oversize skip
python3 -c "open('$WORK/fx1/big.txt','w').write('x' * (3*1024*1024))"
note=$(J scan "$WORK/fx1/big.txt" --json | python3 -c "import json,sys; print(json.load(sys.stdin)['files'][0]['notes'][0])")
case "$note" in "skipped: exceeds"*) ok "oversize skipped with note";; *) bad "oversize note: $note";; esac
rm -f "$WORK/fx1/big.txt"

# 14. rules + errors
J rules | grep -q "MIM-C1" && ok "rules catalog" || bad "rules catalog"
expect_exit "unknown command" 2 J bogus
expect_exit "json+md exclusive" 2 J scan "$WORK/fx1" --json --md
expect_exit "no input" 2 J scan

# 15. depth + max flags accepted
expect_exit "depth flag" 0 J scan "$WORK/fx1/clean_page.html" --depth 1 --max 1000000

echo
echo "e2e: $pass passed, $fail failed"
[ "$fail" = "0" ] || exit 1
rm -rf "$WORK"
exit 0
