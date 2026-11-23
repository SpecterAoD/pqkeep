# Protected HTTP and JSON ingress / gesperrter HTTP-/JSON-Eingang (#147 R4)

DE: Beschluss im Rahmen der beauftragten strikten Laufzeitbehebung: bestehendes HTTP/1-
Protokoll, Routing, Authentisierung und JSON-Semantik erhalten. Kein eigener HTTP-/JSON-
Parser und keine heimliche Abschaltung. Gepinnte Provider gezielt um injizierbare
Speicher-Ownership erweitern; Änderungen und Herkunft im Vendor-Prüfregister festhalten.
EN: Preserve reviewed protocol/parsing algorithms and native compatibility. Extend the
existing pinned providers at their buffer boundaries rather than replacing parsers or
claiming that wrapping a final String protects earlier copies. No new network exposure.

## Ownership / Speicherbesitz

- Hyper: opt-in protected read-buffer interface, selected before the first socket read.
  PQKeep supplies fixed-capacity SecretBytes, using the existing shared page registry.
  Header/body splitting copies only into a new already-locked destination. Bytes owners
  retain their guards through clones, parser errors, disconnects and cancellation.
  No debug output of buffer contents; the normal Hyper API remains compatible for others.
- JSON: bounded root body collector copies frames only into prelocked SecretBytes.
  A narrow pinned serde_json scratch injection keeps escape-decoding/parser scratch locked
  before use and wipes its complete allocation before releasing its guard. Preserve the
  existing parser, UTF-8/escape handling, depth and duplicate/unknown-field rejection.
- Request fields: deserialize passphrases directly into Passphrase; partial request
  failures, early metadata/algorithm rejection and blocking queues own guarded values.
  String-consuming visitors use the existing wiping constructor, no secret error echo.
- Embedding: callers own their upstream transport/body creation. The stock server must
  select the protected path, with no fallback on allocation/lock/parser failure. A router
  cannot retroactively protect memory supplied by an external host; document that boundary.

DE: Ein Byte darf vor einer Sperrbestätigung weder aus dem Socket gelesen noch als
private Kopie in einen neuen Puffer geschrieben werden. Gesperrte Owner müssen vor dem
Freigeben löschen; vorhandene Seitenzähler verhindern gegenseitiges Entsperren. Keine
TLS-/Token-/Bodylimit-Eigenschaft als Ersatz für Speichersperren darstellen.
EN: Preserve host/browser/rate/lockout protections, connection/header/body limits and
timeouts, JSON response/status compatibility, and sanitized errors. No unsafe application
code, security-setting change or additional privilege. Provider extensions are opt-in.

## Validation and remaining boundaries / Prüfung und verbleibende Grenzen

DE: Live-Read-/Split-/Parse-Ownership messen, kleine fragmentierte/chunked/escaped
Anfragen und vorzeitigen Abbruch prüfen. Sperrverweigerung muss vor Read/Kopie/Dispatch
scheitern. Wipe-before-Unlock und Guard-Retention bei Bytes-Klonen und Queue-Drop prüfen.
Alle bisherigen HTTP-/API-/Generate-/Timeout-/Browser-Tests unverändert semantisch erhalten.
EN: Verify vendor archives against pinned Cargo.lock checksums, license/provenance and
exact patches. No passing ordinary HTTP test is a substitute for live lock observation.
Kernel socket buffers, privileged external inspection, compiler registers and the
embedder's own allocations remain explicitly external boundaries, not fabricated proofs.

DE: Dieses ADR ist ein Umsetzungsplan, noch kein Nachweis der vollständigen Behebung.
EN: This ADR records the implementation decision; closure requires actual code and evidence.
