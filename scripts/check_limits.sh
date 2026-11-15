#!/usr/bin/env bash
# DE: Prüft die Projektregeln aus docs/SPEC.md und bricht bei Verstoß mit Exit 1 ab:
#     - Produktionsdateien in src/ max. 300 Zeilen
#     - Testdateien (src/**/*_tests.rs, tests/**) max. 400 Zeilen
#     - keine Testfunktionen oder Inline-Testmodule in Produktionsdateien
#     - keine Binärdateien im Repository (nur versionierte Dateien); Ausnahme: Bilder unter
#       docs/images/ (PNG, JPEG, WebP, höchstens 500 KB, Dateisignatur passend zur Endung)
# EN: Checks the project rules from docs/SPEC.md and fails with exit 1 on violation:
#     - production files in src/ at most 300 lines
#     - test files (src/**/*_tests.rs, tests/**) at most 400 lines
#     - no test functions or inline test modules in production files
#     - no binary files in the repository (tracked files only); exception: images below
#       docs/images/ (PNG, JPEG, WebP, at most 500 KB, file signature matching the extension)
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
# DE: Ausnahme nur für Bilder der Doku (SPEC 5c): Pfad, Endung, Größe und Signatur müssen passen.
# EN: Exception only for documentation images (SPEC 5c): path, extension, size and signature must match.
IMAGE_MAX=512000
allowed_image() { # DE/EN: Bild in docs/images zulässig? / image in docs/images allowed?
  local f="$1" magic
  [[ "$f" =~ ^docs/images/[A-Za-z0-9._-]+\.(png|jpg|jpeg|webp)$ ]] || return 1
  (( $(wc -c < "$f") <= IMAGE_MAX )) || return 1
  magic="$(head -c 12 "$f" | od -An -tx1 | tr -d ' \n')"
  case "${f##*.}" in
    png) [[ "$magic" == 89504e470d0a1a0a* ]] ;;
    jpg|jpeg) [[ "$magic" == ffd8ff* ]] ;;
    webp) [[ "$magic" == 52494646????????57454250 ]] ;;
  esac
}
while IFS= read -r line; do
  file="${line##*$'\t'}"
  if [[ "$file" == docs/images/* ]]; then
    allowed_image "$file" || report "$file: Bild nicht zulässig (PNG/JPEG/WebP, ≤ 500 KB) / image not allowed"
  else
    report "$file: Binärdatei im Repository / binary file in repository"
  fi
done < <(git ls-files --eol | grep -E '^i/-text' || true)

if (( fail )); then
  exit 1
fi
echo "OK: Limits eingehalten / limits respected"
