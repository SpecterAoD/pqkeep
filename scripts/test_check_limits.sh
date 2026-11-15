#!/usr/bin/env bash
# DE: Negativtest für check_limits.sh: baut ein Wegwerf-Repo mit Verstößen und
#     erwartet Exit 1 sowie je eine Meldung pro Verstoß; ein sauberes Repo muss Exit 0 liefern.
# EN: Negative test for check_limits.sh: builds a throwaway repo with violations and
#     expects exit 1 and one message per violation; a clean repo must exit 0.
# Usage: scripts/test_check_limits.sh   (aus dem Repo-Root / from the repo root)
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check_limits.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
git init -q
mkdir -p src tests
printf 'pub fn ok() {}\n' > src/lib.rs
# DE: Zulässiges Bild (PNG-Signatur, klein). EN: Allowed image (PNG signature, small).
mkdir -p docs/images
printf '\x89PNG\r\n\x1a\n\0\0\0' > docs/images/ok.png
git add -A
bash "$SCRIPT" > /dev/null || { echo "FEHLER: sauberes Repo abgelehnt / clean repo rejected"; exit 1; }

printf '#[test]\nfn x() {}\n' > src/inline.rs
printf 'mod tests {\n}\n' > src/inline_mod.rs
seq 1 301 | sed 's|^|// |' > src/long.rs
seq 1 401 | sed 's|^|// |' > tests/long.rs
seq 1 350 | sed 's|^|// |' > src/fine_tests.rs
printf 'a\0b' > blob.bin
printf 'a\0b' > docs/images/fake.png
mkdir -p assets && cp docs/images/ok.png assets/elsewhere.png
{ printf '\xff\xd8\xff\0'; head -c 600000 /dev/zero; } > docs/images/big.jpg
git add -A

set +e
out="$(bash "$SCRIPT" 2>&1)"
code=$?
set -e

expect() {
  grep -q "$1" <<< "$out" || { echo "FEHLER: erwartet / expected: $1"; echo "$out"; exit 1; }
}
[[ $code -eq 1 ]] || { echo "FEHLER: Exit $code statt 1 / instead of 1"; exit 1; }
expect "src/inline.rs: Tests"
expect "src/inline_mod.rs: Tests"
expect "src/long.rs: 301"
expect "tests/long.rs: 401"
expect "blob.bin: Binär"
expect "docs/images/fake.png: Bild nicht zulässig"
expect "docs/images/big.jpg: Bild nicht zulässig"
expect "assets/elsewhere.png: Binär"
if grep -q "docs/images/ok.png" <<< "$out"; then
  echo "FEHLER: zulässiges Bild gemeldet / allowed image reported"
  exit 1
fi
if grep -q "fine_tests.rs" <<< "$out"; then
  echo "FEHLER: *_tests.rs mit 350 Zeilen fälschlich gemeldet / wrongly reported"
  exit 1
fi
echo "OK: check_limits.sh verhält sich wie erwartet / behaves as expected"
