# Protected terminal input / Geschützte Terminaleingabe

DE: Beauftragter #147-Folgeschritt auf signiertem Main31227bc947. Der tatsächliche
console0.16.6-Key-Leseweg erzeugt gewöhnliche Unix-Bytearrays/Escape-Vecs sowie
Windows-INPUT_RECORD-Kopien und inputabhängige UTF16-Fehlerstrings. Root zeigt nur
ErrorKind, keine nachgewiesene Logoffenlegung. Ziel: diesen expliziten privaten
Zwischenspeicher auf Linux und Windows ersetzen, vorhandene Eingaben erhalten.
EN: Existing prelocked output does not protect preceding provider buffers. Keep
public prompt/output APIs; remove console Key values only from password input.
No blanket GUI refusal or claim of full process/OS/compiler protection.

## Files / Dateien

- src/cli/terminal_secret.rs and separate terminal_input/decoder/native modules:
  existing SecretBytes for full output, UTF8 scratch and pending input. Lock every
  owner/descriptor and full capacity before prompt or private input; no ordinary
  private arrays, Vec/String, buffered Stdin reader or unlocked fallback.
- Linux: rustix::io::read directly into protected borrowed slices on stdin, same
  descriptor as terminal_mode. Incremental strict UTF8, bounded escape handling,
  complete backspace, cancel/EOF/invalid input and checked restoration. Preserve
  prompt redirect and stdin-TTY contract. Add rustix event feature only for safe
  poll; pinned package identities unchanged, native syscall/feature audit required.
  Existing poll/ppoll/read/ioctl sandbox policy must not be relaxed.
- Windows: narrow platform/pqkeep-platform input, mode and record modules using
  BorrowedHandle and caller-prelocked byte storage. Align within the whole locked
  allocation, check bounds, avoid whole INPUT_RECORD/KEY_EVENT_RECORD by-value
  copies. Read only initialized fields after successful count/discriminant checks.
  Raw wipe guard before FFI restores every record byte (including padding) before
  any safe byte access/return/unwind. Use volatile writes/fence, not a speculative
  padding read. Root remains forbid(unsafe_code). No additional dependency needed.
- Windows UTF16/repeat state in protected caller bytes; return only public actions,
  byte counts and repeat counts. Encode directly into protected UTF8 scratch.
  Own-console mode guard preserves unrelated bits and explicitly checks restore.
- Separate native/decoder/denial tests; scripts/test_terminal_secret.py PTY tests;
  DE/EN SPEC, memory inventory/documentation, roadmap and CHANGELOG.

## Validation / Prüfung

DE: Vor erstem tatsächlichem Read alle Bereiche gesperrt beobachten. Fragmentierte
UTF8, BMP/supplementäre UTF16, Wiederholungen, Nicht-Tastaturereignisse, Backspace,
ESC/CTRL-C, EOF, ungültige/trunkierte Zeichen und Kapazitätsgrenzen prüfen. Keine
Ersatzzeichen oder geheimen Fehlermeldungen. Wiederherstellung bei Erfolg/Abbruch/
Fehler; Wipe bei normalem/error/unwind-Rückweg; isolierte tatsächliche Sperrverweigerung.
EN: Real Linux PTY no-echo and mode restoration, not only decoder tests. Native
Windows uses own isolated short-lived console child with public synthetic input;
no user-desktop injection/clipboard changes. Assert actual adapter/input coverage,
never passing skip as proof. Observe locked live allocations, never freed or
uninitialized memory. Registry lock observations are not independent OS attestation.

DE/EN: Both strict Clippies/features, fmt/limits/provenance, full Linux/ARM64/Windows
CI and all8 existing fuzz targets on final head. Review pinned source archives and
production feature trees after event activation. Preserve KDF/crypto/formats/API/
normalization/security gates. Complete independently restored bundle and practical
exact-base reverse patch before merge. Signed plan precedes implementation.

DE: R6 beibehaltene Providerzustände/Konstruktion/Mathematik-Scratch, GUI-Helper/
TextBox/echte IME, Betriebssystem-Eingabepuffer und R7 vollständiger Prozess-/Dump-/
Handle-/Peer-Schutz sowie übrige R8-/Compiler-/Stack-/Registergrenzen bleiben offen.
EN: #147/roadmap remain In progress. No installation, rights/ACL/Registry/host-policy
change, sandbox relaxation, deployment or new IPC. Recovery through a separately
reviewed signed revert PR; preserve local work and full backup.

## Native fixture refinement before implementation / Präzisierung vor Fixture-Code

DE: Die Root-Crossprüfung bestätigt das auch für Integrationstests erzwungene
Unsafe-Verbot. Keine Ausnahme hinzufügen. Native Test-FFI stattdessen als eigenes
Konsolenfixture-Example der vorhandenen Plattformcrate; nur öffentliche synthetische
Ereignisse. Root-Test startet dieses in CREATE_NEW_CONSOLE. Fixture prüft alleinige
Konsolenzugehörigkeit vor dem Schreiben und startet den sicheren Root-Testkindprozess
mit derselben eigenen Eingabekonsole. Root verwendet nur sichere Reader-/Modus-APIs.
EN: No Root windows-sys dev dependency or new package. Add one Windows-only CI build
step for the fixture example; retain every existing check, scanner and eight fuzz
targets. Both fixture and Root child use checked timeouts; parent verifies exactly
one actual child test passed, never a successful empty filter. Unsafe remains only
in the platform boundary/fixture. Keep non-Linux/non-Windows existing provider
behavior explicitly OPEN rather than introduce a new Unsupported refusal.

DE: Finale Fixture-Anbindung vor Code: Ein separat vorgebautes Example würde einen
neuen manuellen cargo-test-Vorbereitungsschritt verlangen. Stattdessen schmales
native-input-fixture-Feature derselben Plattformcrate, ausschließlich über Roots
Windows-dev-dependency aktiviert. Keine neue Paketidentität und keine FFI-Ausnahme
in Root. Fixture prüft alleinige eigene Konsolenzugehörigkeit und erlaubt nur fest
vorgegebene öffentliche synthetische Ereignisse; keine beliebigen Secret-Parameter.
EN: This supersedes the example/build-step proposal. Normal Root production feature
trees must exclude the fixture, with/without API. Existing platform CI Clippy/tests
include all features to audit the fixture too; all other gates stay intact. Native
Root integration tests use only the safe fixture API and real protected Input reader,
without prebuild prerequisites. Signed clarification precedes fixture implementation.

## Queued-error remediation before code / Restpufferbehebung vor Code

DE: Zusätzliche echte PTY-Probe zeigt3/3 nach ungültigem UTF8 noch25 öffentliche
Fixturebytes im Eingabepuffer, obwohl der Modus restauriert war. Nicht als erfolgreiche
Fehler-Vertraulichkeit ausgeben. Vor finalem Code: nur bei Fehler/Abbruch und Unwind
bereits wartende Eingaben vor Modusfreigabe verwerfen; erfolgreiche Reads erhalten
vorgetippte Bestätigung. Linux TCSAFLUSH statt NOW nur auf diesen Fehlerwegen, mit
Read-back des sicheren Modus vor Prompt. Windows eigene bestehende CONIN$-Read/Write-
Datei für dokumentiert schreibberechtigte Fehlerbereinigung öffnen, ursprüngliches
Stdin weiter lesen; keine ACL-/Token-/Nutzerrechte ändern. Flush-Rückgabe kontrollieren,
bei fehlgeschlagener Fehlerbereinigung nicht still zum Echo-Modus zurückfallen.
EN: Add true queued-suffix/typed-ahead PTY regressions and native Windows queue-count,
normal-preservation/error-discard tests, including ordinary read-only input handles.
Future bytes arriving after the operation, OS-owned buffers/real IME and full
process/isolation remain OPEN. Existing local-v1 sixteen passes are historical once
this code changes. Signed clarification precedes the queued-error implementation.

## Native failure diagnostics / Native Fehlerdiagnose

DE: Windows-CI am Heada78fb8f scheitert im eigenen Konsolenkind; der Elternprozess
prüft dessen Status vor dem Lesen der gepipeten Testdiagnose und verdeckt damit
die konkrete Ursache. Vor Änderung: Kind immer vollständig einsammeln und erst
danach Status und tatsächlichen Ein-Test-Erfolg prüfen. Nur feste öffentliche
Fixture-Diagnose erfassen; keine echten Geheimnisse oder fremde Konsole verwenden.
EN: Add an early Windows-only run of the same native integration target, with and
without API, after both strict Clippies. Preserve the later full test suites,
worker/lock budgets, scanners and eight fuzz gates. This is earlier failure
feedback, never a passing skip or substitute for final-head native acceptance.
Production behavior stays unchanged until the actual failure is diagnosed.

DE: Native Diagnose209b3b2 lokalisiert AccessDenied beim Read-only-CONIN$-Modusguard,
nach erfolgreichen Record-/Unicode-/Queue-Proben. Vor Produktionsänderung: Setzen
und Restore über das bereits vor Eingabe geöffnete eigene Read/Write-CONIN$-Handle;
Modus zusätzlich über das ursprüngliche geliehene Eingabehandle nachprüfen. Stdin
weiter unverändert lesen; keine Handle-Rechte/ACLs/Tokens ändern oder Tests entfernen.
EN: Retain both-handle read-back, actual input-capability checks and checked error
flush before mode release. Native read-only input remains mandatory acceptance,
not a skip. Re-run strict platform/Root checks and complete final-head native CI.
API documentation lists GENERIC_READ for SetConsoleMode, but native access denial
is not waived on that basis. Signed clarification precedes production change.
