# Checked Linux startup / Geprüfter Linux-Start

DE: R7-Teil im gemeinsamen Draft355. Eigene begrenzte Seccomp-Probe hat den
bisherigen Fehler tatsächlich reproduziert: Verweigerte Core-Limit-Rücklesung
führt bei der bisherigen rustix-getrlimit-Verwendung zu Panic101. Der unveränderte
CLI-Binaryhash und alle verwendeten rlib-/Quellhashes sind im lokalen Baseline-
Nachweis erfasst. Kein erfolgreicher Verweigerungsschutz aus diesem Fehler abgeleitet.
EN: The failed reproduction is retained. The baseline executable and dependency
artifacts remained byte-identical; probe compilation wrote separate evidence only.

## Implementation / Umsetzung

DE: Linux-Observe verwendet eine fallible libc-getrlimit-Abfrage mit geprüftem
Rückgabewert und echtem SDK-Typ. Initialisierte öffentliche Policy-Daten sind
keine privaten Anwendungsdaten. Ein notwendiger FFI-Aufruf bleibt ausschließlich
im Plattformmodul; Root-forbid unverändert. Fehler/Unbekannt bestätigt kein Flag.
EN: Direct library observation remains read-only. No implicit host-policy mutation
is added. Existing permitted IPC_LOCK handling is unchanged; no new privilege or
capability expansion. Core-limit and dumpability capabilities remain separate
from the explicitly partial Windows WER observation.

DE: Linux-CLI verweigert jetzt zwingend vor argv-Sammlung, Dialogen oder Secret-
Verarbeitung, wenn der eigene Startschutz beide Core-Limits auf0 und NotDumpable
nicht tatsächlich setzt und zurückliest. Kein reiner Warnpfad und kein
--no-sandbox-Bypass. Statischer zweisprachiger Fehler auf stderr, Exit1; keine
Argumente nur für die Fehlerformatierung einlesen, keine Teilausgabe.
EN: This includes help/version under an unverified Linux startup because private
arguments must not be collected first to select an exemption. Successful CLI/JSON
behavior is retained. Windows flows stay available while verified Windows/native
helper support is still being developed; this is not a Windows capability claim.

## Actual tests / Tatsächliche Tests

DE: Je ein eigener exec-Prozess verweigert PR_SET_DUMPABLE, PR_GET_DUMPABLE oder
die lesende Core-prlimit64-Abfrage mit echtem EPERM. Keine simulierten Rückgaben.
Die CLI muss sichtbar vor Eingabe/Zielausgabe abbrechen, ohne Panic; Elternlimits
und Dumpable-Zustand bleiben unverändert. Timeout beendet/wartet nur das eigene
Kind. exec ersetzt den Probeprozess, sodass kein Enkel zurückbleibt.
EN: Test restrictions apply only to the own short-lived probe thread/process;
no host policy, account, Registry or unrelated process is changed. Normal actual
process hardening/idempotence remains tested. Initial source-bound runtime check
passed all three refusal modes and the normal case on881 unchanged sources.

DE: Finaler integrierter Checkpoint linux-cli-gate-v3:888 Rust-/Manifest-Hashes
über14 erfolgreiche Prüfungen unverändert. Vier strenge Root-Lints (Linux/Windows,
API/ohne API), zwei Plattform-Lints sowie je22 CLI-/Hardening-Integrationstests
pro Featurekonfiguration bestanden. Alle drei echten Verweigerungen ausgeführt.
EN: Native metadata integration is included. Format, source limits and unchanged
provider inventory/matrix gates pass. Native Linux/ARM startup acceptance pending. Library-host capability contracts, verified Windows process support,
native password helpers and all remaining R8 metadata remain open. No complete
P1–P5/R7/R8/147 acceptance and no partial Main merge.
