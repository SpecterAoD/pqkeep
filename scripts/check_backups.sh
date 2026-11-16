#!/usr/bin/env bash
# DE: Backup-Monitoring; Aufruf und Voraussetzungen: docs/SERVER.md.
# EN: Backup monitoring; usage and prerequisites: docs/SERVER.md.
set -euo pipefail

fail() {
    printf '%s\n' "$1" >&2
    exit "${2:-1}"
}

(( $# >= 3 )) || fail 'Aufruf / usage: check_backups.sh PQKEEP KEY_FILE PASS_FILE [SOURCE ...]' 2
pqkeep=$1
key=$2
pass_file=$3
shift 3
(( $# > 0 && $# <= 1000 )) || fail 'FEHLER / ERROR: 1–1000 Quellen erforderlich / sources required' 2
command -v jq >/dev/null 2>&1 || fail 'FEHLER / ERROR: jq fehlt / unavailable'
command -v "$pqkeep" >/dev/null 2>&1 || fail 'FEHLER / ERROR: pqkeep fehlt / unavailable'

# DE: Bash-Variablen entfernen NUL-Bytes; bis zum Parsen die exakten Bytes behalten.
# EN: Bash variables discard NUL bytes; retain exact bytes until parsing.
umask 077
report_file=$(mktemp) || fail 'FEHLER / ERROR: temporäre Datei / temporary file'
trap 'rm -f -- "$report_file"' EXIT
trap 'exit 1' HUP INT TERM

# DE: Kein eval, keine Pipe vom Programm zum Parser; Exit-Code sofort sichern.
# EN: No eval, no program-to-parser pipeline; save the exit code immediately.
status=0
if "$pqkeep" --batch check --json --key "$key" --passphrase-file "$pass_file" -- "$@" >"$report_file" 2>/dev/null; then
    status=0
else
    status=$?
fi
failure=$status
(( failure != 0 )) || failure=1
sources=$(jq -cn --args '$ARGS.positional' -- "$@") || fail 'FEHLER / ERROR: jq' "$failure"

# DE: Nur validierte Felder ausgeben, niemals Rohdaten oder Parserfehler.
# EN: Print validated fields only, never raw data or parser errors.
if ! message=$(jq -ers --argjson status "$status" --argjson sources "$sources" '
    def integer: type == "number" and . >= 0 and . == floor;
    def kinds: ["ok", "error", "usage", "decrypt_failed", "weak_passphrase",
                "target_exists", "no_windows", "invalid_signature"];
    def error_ok:
        type == "object" and (.code | integer and . >= 1 and . <= 7)
        and .kind == kinds[.code];
    def require($valid): if $valid then . else error("invalid") end;
    require(length == 1) | .[0]
    | require(type == "object")
    | require(.schema == "pqkeep-json/1" and .command == "check"
        and (.ok | type == "boolean")
        and (.exit_code | integer and . <= 7)
        and .exit_code == $status and .ok == ($status == 0))
    | if has("error") then
        require(.ok == false and (.error | error_ok)
            and .error.code == .exit_code and (has("results") | not)
            and (has("summary") | not))
        | "FEHLER / ERROR: Aufruf gescheitert / command failed (\(.error.kind)); "
          + "Quellen nicht bestätigt / sources unverified: \($sources | tojson)"
      else
        require((.results | type == "array") and (.summary | type == "object"))
        | require((.results | length) == ($sources | length)
            and [.results[].source] == $sources
            and all(.results[]; type == "object" and (.ok | type == "boolean")
                and if .ok then (has("error") | not) else (.error | error_ok) end))
        | require((.summary.total | integer) and (.summary.ok | integer)
            and (.summary.failed | integer)
            and .summary.total == (.results | length)
            and .summary.ok == ([.results[] | select(.ok)] | length)
            and .summary.failed == ([.results[] | select(.ok == false)] | length)
            and .ok == (.summary.failed == 0)
            and .exit_code == ([.results[] | select(.ok == false) | .error.code][0] // 0))
        | (.results[] | select(.ok == false)
            | "FEHLER / ERROR: \(.source | tojson) (\(.error.kind))"),
          "\(if .ok then "OK" else "FEHLER / ERROR" end): "
          + "gesamt / total=\(.summary.total), OK=\(.summary.ok), Fehler / failed=\(.summary.failed)"
      end
' "$report_file" 2>/dev/null); then
    fail "FEHLER / ERROR: JSON fehlt oder ist inkonsistent / missing or inconsistent JSON (pqkeep=$status)" "$failure"
fi
printf '%s\n' "$message"
exit "$status"
