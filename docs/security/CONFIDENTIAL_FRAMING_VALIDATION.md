# Confidential framing / Vertrauliches Framing

DE: Teilbaustein des freigegebenen gemeinsamen R7/R8-Plans in Draft #355,
kein Abschluss von M5 oder R7/R8. R6-Providerverträge bleiben erhalten.
EN: Component within the approved joint plan, not complete M5/R7/R8 acceptance.

## Actual ownership / Tatsächliches Eigentum

| Path / Pfad | Protection / Schutz |
|---|---|
| `confidential_framing::message` | Header SHA3-512 in LockedHash; domain, hash and length fields encoded directly into prelocked output, no private `to_le_bytes` array. |
| `confidential_framing::trailer` | Both little-endian lengths and unchanged magic written into prelocked SecretBytes; no returned ordinary array. |
| `format_v4::check_trailer` | Borrowed byte decoding into scalar words without an intermediate eight-byte array. |
| `tail_v4_drain` | Public-empty State prelocked before private population; held/written/zero counts retained in that state. Existing locked buffer truncated after EOF rather than copied into a second tail allocation. |
| `stream_io` | Writer cursor/total and reader cursor/released retained in a prelocked Progress state; checked arithmetic before hash/copy/output for the affected operation. Destructor wipes before unlock. |

DE: Aufrufer erhalten bei ausdrücklich angeforderten `written()`, `position()`,
`finish()` und Trailer-Prüfung weiterhin skalare Längen. Kurzlebige skalare
Berechnungen und Compiler-/Registerkopien werden nicht als vollständig beseitigt
behauptet. Öffentliche Nonces, Blockzähler und Ciphertext-Geometrie bleiben vom
privaten Nutzlängenvertrag getrennt. Andere bekannte private Datensätze bleiben
konkrete offene Arbeit, keine umbenannte Compilergrenze.
EN: Scalar API disclosure is intentional; retained counters are protected. This
does not claim control over all compiler/register copies, caller-owned buffers,
OS transport buffers, remaining reports/serialization, native paths or lock-registry
records. Those joint-plan rows remain open.

## Rust API migration / Rust-API-Migration

DE: `format_v4::trailer(payload, pad)` liefert statt `[u8; 24]` jetzt
`Result<SecretBytes>`. Konstruktion mit `?` prüfen, Ausgabe mit `expose()` nur
ausleihen; notwendiges eigenständiges Duplikat fallibel mit
`SecretBytes::from_slice(original.expose())?` erstellen. Kein Clone-/Array-Fallback.
EN: Propagate the construction error, borrow for encryption, and use fallible
protected duplication only when independent ownership is required. Existing
internal callers and format tests migrate together. No format-version, endian,
domain, padding, trailer magic, signature-equation or CLI/JSON schema change.

## Verification / Prüfung

DE: Testfälle prüfen öffentliche Referenzbytes an Integergrenzen, vorhandene
Padding-/Manipulations-/Absenderregeln, reale AEAD-Chunkgrenzen und tatsächliche
Owner-/Byte-Sperren. Eigene begrenzte Linux-Kinder prüfen Verweigerung bei echtem
Nullbudget, Fehler und Unwind mit exaktem Sperrzähler-Baseline-Rücklauf;
Elternlimits bleiben unverändert. Assertions geben keine privaten Bytes/Adressen aus.
EN: Source-bound test and lint results are retained outside Git under
`analysis/issue-147-r7-r8-20261127T182246Z`. Native final joint acceptance is still
required; defining a test is not a claim that its final source version has passed.

DE: Lokaler Quellenstand vor Veröffentlichung: neun Befehle erfolgreich,
Quellhashes vor/nach dem gesamten Lauf identisch. Strenges All-Target-Clippy
mit/ohne API, jeweils 67 Datei- und fünf STREAM-Gruppen bestanden; zusätzlich
29 Integrationsfälle für Chunk-/Fehler-/v4-/verborgene und öffentliche Signaturen.
Explizit ignorierte Kindfunktionen werden durch ihre erfolgreichen Eltern
begrenzt und tatsächlich aufgerufen. Root-/Plattform-Formatprüfung, Limits,
Diff und unveränderte Provider-Herkunftsprüfung erfolgreich. Ein erster
Lintfehler im Test wurde ohne private Fehlerausgabe korrigiert; Belege erhalten.
EN: Checkpoint `confidential-framing-v2.json` and complete command logs bind
these results to source hashes, with the separate format/provider proof. Native
final acceptance of this newer framing component remains pending. Earlier native
signature-head Rust suites passed, but their jobs correctly failed on the omitted
ML-DSA patch-manifest entries; those exact entries are corrected without changing
upstream provenance, other packages, scanner rules or the verification script.
