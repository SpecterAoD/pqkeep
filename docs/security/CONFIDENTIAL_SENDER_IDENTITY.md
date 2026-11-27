# Confidential sender identity / Vertrauliche Absenderidentität

DE: Teilbehebung der Identitäts-Retention aus M4 im gemeinsamen R7/R8-PR355.
Keine vollständige M4-Abnahme: vertrauliche Signaturkodierung und -verifikation
haben weiterhin gesondert zu bearbeitende Provider-/Scratchpfade. M5-Ausgaben
und Reportzähler sind ebenfalls noch nicht vollständig geschützt.
EN: Local implementation in progress, not a complete R8 or issue147 closure.

DE: Aktueller Folgebaustein: Signaturkodierung, Schlüsselaufbau und vollständige
Verifikations-Scratchpfade sind jetzt zusätzlich lokal implementiert; ihre native
Gesamtabnahme ist noch offen. Siehe [HIDDEN_SIGNATURE_VALIDATION.md](HIDDEN_SIGNATURE_VALIDATION.md).
EN: Fixed-length identity equality reuses subtle2.6.1 in both feature configurations;
noncanonical identity lengths are refused before allocation. No version change.

## Data flow / Datenfluss

DE: Vorher kopierte hidden_sender den verborgenen öffentlichen Schlüssel aus
dem gesperrten Trailer in einen gewöhnlichen Signer.public_key-Vec. fingerprint
lieferte anschließend einen gewöhnlichen Schlüssel-ID-Vec; SignedBy erlaubte
Clone und Debug der Identität. Jetzt den geliehenen Trailer-Schlüssel direkt mit
LockedHash<Sha3_256> verarbeiten. Hashzustand und Ausgabe vor Befüllung sperren;
auch der SecretBytes-Owner des Ergebnisses liegt in einem vorab gesperrten
SecretState. Keine zwischenzeitliche Signer-/Schlüsselkopie und keine normale
Hashausgabe. Dieselbe Konstruktion gilt für den geprüften öffentlichen v3-Absender.
EN: Public v3 header Signer remains intentionally public and unchanged. Its
verified result uses the same protected identity type as hidden v4 senders.

DE: Shared HiddenResult hält den tatsächlichen RefCell<Option<SignedBy>>-Slot
in stabilem SecretState. Rc teilt nur Ownership; kein frei kopierbarer Identitäts-
Payload. Leerer Slot vor der Sperre, danach store/take. Bei Ersetzung und Ende
werden verschachtelte Owner gelöscht, bevor SecretState die gesamten früheren
Recordbytes einschließlich Padding löscht und entsperrt. Die erwartete Identität
bei --signer wird ebenso fallibel gesperrt; Konstruktorfehler werden weitergegeben.
EN: Source key and caller-owned expected public-key inputs are borrowed; this
does not retrospectively lock caller allocations. Shared ownership is separate
from disclosure. No new dependency, unsafe code or cryptographic equation.

## Rust migration / Rust-Migration

DE: SignedBy.key_id: Vec<u8> wird durch eine private gesperrte Ownership und
SignedBy::key_id() -> &[u8] ersetzt. Ausgabe bewusst ausleihen, statt impliziter
Dereferenzierung oder Serialisierung. SignedBy::try_duplicate() -> Result<Self>
ersetzt Clone; Debug gibt nur SignedBy([REDACTED]) aus. Report implementiert deshalb
ebenfalls kein infallibles Clone mehr. Bestehende Rust-Caller müssen Feldzugriffe
in Methodenaufrufe ändern und gewünschte Kopien ausdrücklich fallibel behandeln.
EN: This is an intentional Rust source API change under the approved joint plan
and the open versioned-API work in #98. CLI text, JSON signer hex, authenticated
output order, header/trailer bytes and public key fingerprints stay compatible.

## Acceptance / Abnahme

DE: Eigene Tests vergleichen tatsächliche Hashbytes mit dem unabhängigen
öffentlichen Sha3_256-Digest, prüfen konkrete Owner-/erste-/letzte Byteadressen,
redigiertes Debug, unabhängige fallible Kopie und stabilen geteilten Ergebnis-Slot.
Zusätzlicher begrenzter Linux-Kindprozess prüft echten Unwind und tatsächliche
Sperrverweigerung für Duplikat, Ergebnis-Slot und Hashkonstruktion. Das Elternlimit
bleibt unverändert. Bereits gesperrte gemeinsame Seiten dürfen zunächst Erfolg
liefern; echte spätere Verweigerung ist zwingend, ohne Skip/Fallback.
EN: Tests and lint results are recorded separately with the exact source checkpoint
in the protected analysis directory. Native Windows/ARM64 and final joint acceptance
remain pending; compilation alone is not native execution.
