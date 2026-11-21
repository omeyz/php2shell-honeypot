#!/usr/bin/env bash
# Verify the analysis parser scores the known request shapes correctly.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
out=$(python3 -I analysis/extract_php2shell.py --raw samples/raw 2>/dev/null)

score_for() { printf '%s\n' "$out" | python3 -I -c '
import sys, json
want = sys.argv[1]
for line in sys.stdin:
    r = json.loads(line)
    if want in r["source"]:
        print(r["score"], r["verdict"], ",".join(r["indicators"])); break
else:
    print("0 none -")
' "$1"; }

chk() { # name, file-substr, expected verdict
  read -r s v i <<<"$(score_for "$2")"
  if [ "$v" = "$3" ]; then echo "  PASS  $1 (score $s, $v)"
  else echo "  FAIL  $1: expected $3, got $v (score $s, ind=$i)"; fail=1; fi
}

echo "[parser] verdicts"
chk "benign GET is not reported"        "01-benign-get"            "none"
chk "legit upload_progress stays low"   "02-legit-upload-progress" "suspicious"
chk "signature-shaped first request"    "03-signature-shaped"      "likely"
chk "signature-shaped second request"   "04-signature-shaped"      "likely"

echo "[parser] two-request pairing"
if python3 -I analysis/extract_php2shell.py --raw samples/raw 2>&1 >/dev/null \
   | grep -q "sessions with 2+ requests"; then
  echo "  PASS  pairing reported"
else
  echo "  FAIL  pairing not reported"; fail=1
fi

echo "[parser] ordering: attack shape must outscore the legit one"
a=$(score_for "03-signature-shaped" | cut -d' ' -f1)
b=$(score_for "02-legit-upload-progress" | cut -d' ' -f1)
if [ "$a" -gt "$b" ]; then echo "  PASS  $a > $b"; else echo "  FAIL  $a !> $b"; fail=1; fi

echo
[ "$fail" = 0 ] && echo "ALL PARSER TESTS PASSED" || echo "SOME PARSER TESTS FAILED"
exit "$fail"
