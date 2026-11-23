# Locked secret memory / Gesperrter Secret-Speicher

## Scope and authorization / Umfang und Freigabe

DE: Behebt die aus dem #83-Vorab-Audit stammenden konkreten Speicherbefunde im Umfang von
#147/#148. Der Eigentümer hat Behebung, strengere Regeln, Tests und Merge nach main ausdrücklich
beauftragt. Der Vorabplan steht in `LOCKED_SECRETS_PLAN.md`. Kein Stream-Format oder #83-Feature,
keine Crate-Auslagerung, kein Deployment und keine Änderung von Hostrechten oder Schutzregeln.

EN: Addresses the concrete #83 pre-audit memory findings under #147/#148. Owner explicitly
authorized strict hardening, validation and merge to main. No stream format/feature, core extraction,
deployment, host privilege change or repository-protection change.

## Invariants / Sicherheitsregeln

1. DE: Ohne vollständige Seitensperre keine Secret-Instanz und keine Operation mit neuen Secrets.
   EN: No secret instance or processing of new secrets without full page locking.
2. DE: SecretBytes/typisierte SecretBuffer wachsen nicht; vor Eingabe/Schreiben reservieren und sperren.
   EN: SecretBytes/typed SecretBuffer never grow; allocate and lock before input/writing.
3. DE: Löschen beim Wiederverwenden/Freigeben bleibt zusätzlich erhalten: wipe → unlock → free.
   EN: Retain wiping on reuse/release in addition to locking: wipe → unlock → free.
4. DE: Lock-/Allokationsfehler ergeben einen bereinigten MemoryLock-Fehler, keinen ungesperrten Fallback.
   EN: Lock/allocation failure returns a sanitized MemoryLock error, never an unlocked fallback.
5. DE: Alte Format-/Ableitungsbytes bleiben gleich. SecretBytes-Konstruktoren sind jetzt fallibel.
   EN: Existing format/derivation bytes are unchanged. SecretBytes constructors are now fallible.

## Data flow / Datenfluss

| Boundary | Implementation / Umsetzung |
|---|---|
| Argon2 | Caller-owned typed locked Block storage passed to existing RustCrypto API; entire working allocation wiped while locked. |
| HKDF/HMAC | Existing provider extract/expand steps with locked HMAC state, scratch, PRK and output; no hidden key-state cloning. |
| AES-GCM/STREAM | Stable locked provider state; plaintext decrypted in place directly inside SecretBytes. |
| Archive/STREAM buffers | Explicit buffers fixed/locked; consumed encrypt buffer wiped. Outer std buffers and allocating AEAD copies remain audit A1/A2. |
| stdin passwords | Raw duplicated OS handle, bounded direct reads into locked memory; no stdio line buffering or read-ahead into the next secret. |
| password files | Existing owner/type/mode checks, bounded direct reads into locked storage; no growing Vec/String. |
| terminal | Existing console provider reads keys without echo; full input and confirmation stay in locked buffers. |
| generated password | Locked output and RNG pool; no intermediate password String. |
| password assessment | Character/lowercase/leet/special-character and dictionary text copies use locked typed/byte buffers; evaluate fallibly during construction, retain only non-secret assessment metadata. |
| normalization | Existing NFKC behavior retained; normalized output goes directly into pre-locked storage. |

DE: Provider-Lokalpatches sind vollständig in `vendor/README.md` dokumentiert. Kein eigener
Argon2-, AES-, SHA3- oder Zufallsalgorithmus. Der HKDF-Adapter liefert exakt den im bisherigen
Format vorgesehenen ersten Expand-Block. Gegenproben müssen den bisherigen Vertrag bestätigen.
EN: Provider patches are documented with provenance; no replacement Argon2/AES/SHA3/RNG.
The HKDF adapter returns exactly the first expand block required by current formats.

DE: [Audit #147](SECRET_LIFETIME_AUDIT.md) erfasst weitere vorgelagerte Kopien, darunter
Rekey-, Signatur-Hash-, HTTP-/Tokenpfade und Provider-Konstruktion. Diese Tabelle belegt
konkrete gesperrte Speicherorte, keine lückenlose Sperre aller Secret-Kopien. Nacharbeit
ist erforderlich; die strenge Sperrpolicy bleibt bestehen.
EN: Audit147 records remaining rekey/hash/HTTP/token/provider-construction copies. Evidence
for specific locked allocations does not establish complete coverage; retain strict policy.

## Platform behavior / Plattformverhalten

DE: Linux benötigt ausreichend bereits erlaubtes RLIMIT_MEMLOCK für alle gleichzeitig lebenden
Secrets und den gesamten KDF-Arbeitspuffer. Das Programm erhöht weder Limits noch Rechte.
Mit zu kleinem Budget schlägt die Operation sicher fehl. KDF-Parameter werden niemals reduziert.
Windows fordert beim eigenen Prozess Working-Set-Kapazität vor dem Sperren an; dies kann das OS
verweigern und dann wird abgebrochen. Keine Privilegien-/Token-Manipulation, kein Admin-Zwang.
EN: Linux requires an existing sufficient lock budget; no limit/privilege elevation or KDF downgrade.
Windows requests current-process working-set capacity before locking and fails if denied.

DE: Seitensperren verhindern keinen kompromittierten Administrator, Kernelzugriff, Ruhezustands-
abbilder oder alle Compiler-/Register-/Provider-Stackkopien. Abort/SIGKILL führt keine Destruktoren
aus. Das sind technische Systemgrenzen, keine akzeptierten ungesperrten Ausführungspfade:
jede vom Programm verwaltete Secret-Instanz muss gesperrt sein oder ihr Aufruf scheitern.
Die externe OS-/Terminal-/Unicode-/Provider-Implementierung wird damit nicht vollständig auditiert.
EN: Locking does not defeat a compromised administrator/kernel, hibernation, every compiler/register/
provider stack copy or abort/SIGKILL destructor bypass. These system limits do not permit an unlocked
application fallback. This change does not claim a complete audit of external providers or the OS.

## Acceptance and rollback / Abnahme und Rückweg

DE: Lock-Verweigerung, typisierte wipe-before-unlock-Reihenfolge, begrenzte Eingaben/Lesefehler,
Mehrzeilen-Pipes, HKDF-Äquivalenz, unabhängige KATs, vollständige CLI/API-/v1/v2/v3-Regressions-
und native Windows-/Linux-Tests sind erforderlich. Bestehende Matrixnachweise nicht hochstufen,
bevor die konkreten neuen Tests ausgeführt wurden. Neue Checks und tatsächliche Resultate im PR.
EN: Require denied-lock, typed wipe-before-unlock, bounded-input/error, multi-line pipe, HKDF
equivalence, independent KAT and full CLI/API/v1/v2/v3/native platform regressions. Report actual results.

DE: Rückweg ist ein geprüfter signierter Revert-PR; keine Datenmigration. Alte Schlüssel/Archive
bleiben bytekompatibel. Ein Revert hebt diese strengere Policy wieder auf und muss ausdrücklich
als Sicherheitsrücknahme bewertet werden; nicht bei Ressourcenproblemen automatisch zurückfallen.
EN: Reviewed signed revert, no data migration. Reverting also removes the stricter security policy;
never automatically fall back because locked memory is unavailable.

DE: Ausschließlich kurzlebige Linux-GitHub-CI-Testprozesse erhalten nach ausdrücklicher
Eigentümerfreigabe vom 22.11.2026 ein Memlock-Budget von 2 GiB. `ci_locked_exec.py` setzt
mit sudo/prlimit nur sein eigenes Prozesslimit und startet Tests mit unveränderter,
unprivilegierter Benutzer-ID. Kein sudo außerhalb `GITHUB_ACTIONS=true`, keine persistenten
Systemänderungen. Negativtests mit Limit null bleiben unverändert verpflichtend.
EN: Owner explicitly approved a 2 GiB memlock budget solely for ephemeral Linux GitHub CI
test processes. The wrapper adjusts only its own limit, then executes unprivileged tests.
No local elevation or persistent settings; zero-budget denial tests remain mandatory.

DE: Linux hält den Raw-/No-Echo-Modus mittels vorhandener sicherer rustix-Termios-API
vor dem Prompt bis zum Ende jeder vollständigen Eingabe. Normale Fehler- und Erfolgswege
prüfen die Wiederherstellung. Ctrl-C wird als Taste behandelt, sodass die Guards laufen.
Windows nutzt die vorhandene Console-Input-Event-API des Providers, keinen Zeilenleser.
EN: Linux holds raw/no-echo mode from before the prompt across the whole input via the
existing safe rustix termios API, checks restoration on normal error/success paths, and
handles Ctrl-C as a key so guards run. Windows retains provider console-input events.

DE: Die anschließende Freigabe „Weiter“ umfasst den vorgelegten Container-Diff:
kurzlebige CI-Pakettestcontainer erhalten dasselbe 2-GiB-Prozessbudget via `--ulimit`;
keine zusätzlichen Capabilities/privilegierten Container. Paket-Nutzungstests bleiben
unprivilegiert. Container und Prozesslimits verschwinden nach dem Job.
EN: The subsequent approval covers the presented container diff: ephemeral package-test
containers receive the same 2 GiB process budget through `--ulimit`, with no added
capabilities or privileged containers; usage tests remain unprivileged.

DE: Der CI-Starter akzeptiert nur feste Testprofile; keine freien Befehle oder zusätzlichen
Argumente. Unbekannte Profile werden vor sudo und vor Prozessstart abgewiesen. Test-,
Monitoring-, Terminal-, Smoke- und Fuzz-Argumente sind im Code festgelegt; Fuzz-Toolchain
und bestehende 60-/600-Sekunden-Budgets bleiben gepinnt. Root-Testprozesse werden abgewiesen.
EN: CI runner accepts fixed test profiles only, rejecting unknown profiles/extra arguments
before elevation or execution. Commands/arguments are fixed; pinned fuzz toolchain and
existing 60/600-second budgets remain. Refuse root test processes.
