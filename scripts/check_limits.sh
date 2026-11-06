#!/usr/bin/env bash
# DE: Prüft die Projektregeln aus docs/SPEC.md und bricht bei Verstoß mit Exit 1 ab:
#     - Produktionsdateien in src/ max. 300 Zeilen
#     - Testdateien (src/**/*_tests.rs, tests/**) max. 400 Zeilen
#     - keine Testfunktionen oder Inline-Testmodule in Produktionsdateien
#     - keine Binärdateien im Repository (nur versionierte Dateien)
# EN: Checks the project rules from docs/SPEC.md and fails with exit 1 on violation:
#     - production files in src/ at most 300 lines
#     - test files (src/**/*_tests.rs, tests/**) at most 400 lines
#     - no test functions or inline test modules in production files
#     - no binary files in the repository (tracked files only)
# Usage: scripts/check_limits.sh   (aus dem Repo-Root / from the repo root)
set -euo pipefail

PROD_MAX=300
TEST_MAX=400
fail=0

report() { # DE/EN: Verstoß melden / report violation
  echo "FEHLER / ERROR: $*" >&2
  fail=1
}

count_lines() { # DE: physische Zeilen inkl. letzter Zeile ohne Umbruch / EN: physical lines
  awk 'END { print NR }' "$1"
}

check_file() { # file, max
  local n
  n=$(count_lines "$1")
  if (( n > $2 )); then
    report "$1: $n Zeilen / lines (max $2)"
  fi
}

while IFS= read -r -d '' f; do
  case "$f" in
    *_tests.rs)
      check_file "$f" "$TEST_MAX"
      ;;
    *)
      check_file "$f" "$PROD_MAX"
      # DE: Testattribute (#[test], #[tokio::test] …) und Inline-Testmodule verboten.
      # EN: Test attributes (#[test], #[tokio::test] …) and inline test modules forbidden.
      if grep -nE '#\[([a-z_]+::)?test\]|mod[[:space:]]+[a-z_]*tests?[[:space:]]*\{' "$f"; then
        report "$f: Tests in Produktionsdatei / tests in production file"
      fi
      ;;
  esac
done < <(find src -name '*.rs' -print0)

if [[ -d tests ]]; then
  while IFS= read -r -d '' f; do
    check_file "$f" "$TEST_MAX"
  done < <(find tests -name '*.rs' -print0)
fi

# DE: Binärdateien: Git-Erkennung (i/-text = binär, z. B. NUL-Bytes) für versionierte Dateien.
# EN: Binary files: Git detection (i/-text = binary, e.g. NUL bytes) for tracked files.
while IFS= read -r line; do
  report "${line##*$'\t'}: Binärdatei im Repository / binary file in repository"
done < <(git ls-files --eol | grep -E '^i/-text' || true)

if (( fail )); then
  exit 1
fi
echo "OK: Limits eingehalten / limits respected"
