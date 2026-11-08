# U0-1: Testvertrag / Test contract

DE: Jede Zeile ist ein verpflichtender Testfall mit Sollwert. `reference` bedeutet
ausführbare Python-Referenzprüfung in diesem PR; `planned` bedeutet **noch nicht
implementiert oder ausgeführt**, nicht „bestanden“. Alle Varianten einer Zeile
sind einzeln zu parametrisieren. Ein Roundtrip ersetzt keine unabhängigen Vektoren.
EN: Every row is a required case with an expected result. `reference` means an
executable Python reference check in this PR; `planned` means **not implemented
or executed**, not passed. Parameterize every variant separately. Round trips
never replace independent vectors.

DE: Referenztests prüfen Kodierung, Grenzen, Recovery-Text, Rollen/Domänen und
HKDF. Sie beweisen weder Rust-v2-Unterstützung noch TPM/FIDO2-Sicherheit. Die
Zählung der Testmethoden ist nicht die Anzahl späterer parametrisierter Core-Fälle.
EN: Reference tests check encodings, limits, recovery text, roles/domains and
HKDF. They prove neither Rust v2 support nor TPM/FIDO2 security. Test-method count
is not the number of future parameterized core cases.

| ID | Fall / Case | Soll / Expected | Phase | Status |
|---|---|---|---|---|
| R01 | L-Präfix: leer, ASCII, UTF-8 / empty, ASCII, UTF-8 | u32 LE, Byte- statt Zeichenzahl / byte not character length | #39 | reference |
| R02 | file-Descriptor | exakte Referenzbytes / exact reference bytes | #39 | reference |
| R03 | alle Profile, key/file-Domäne, normal/recovery / all profiles/domains/roles | festgelegte Rollen und getrennte AAD / fixed roles, distinct AAD | #39 | reference |
| R04 | unbekanntes Profil, falsche Nonce-/Hüllenlänge / unknown profile, wrong nonce/wrap size | Ablehnung / reject | #39 | reference |
| R05 | file mit Hardwaredaten/Recovery, Hardware ohne Daten/Recovery / inconsistent descriptor | Ablehnung / reject | #39 | reference |
| R06 | gleiche normale/Recovery-Nonce / duplicate nonces | Ablehnung / reject | #39 | reference |
| R07 | Gesamtgrenze 65535/65536/65537 und Providerdaten >65536 / total and provider bounds | Grenze inklusive / inclusive limit, oversize rejects | #39 | reference |
| R08 | Änderung jedes M-Bytes / mutate every M byte | andere AAD / different AAD | #39 | reference |
| R09 | Änderung jeder Hülle / mutate either wrap | WrapAAD stabil, PayloadAAD geändert / stable wrap AAD, changed payload AAD | #39 | reference |
| R10 | RFC5869 SHA-256 Fall 1 / case 1 | veröffentlichter Sollwert / published expected value | #39 | reference |
| R11 | HKDF-SHA3 key/file × file/tpm/fido2/recovery | feste Referenzwerte, verschiedene Ergebnisse / fixed independent values, distinct outputs | #39 | reference |
| R12 | Recovery 0/31/32/33 Bytes; falsche Kennung / sizes, wrong marker | nur exakt 32 / exactly 32 only | #39 | reference |
| R13 | Recovery CRLF/BOM/Leerraum/mehrere Zeilen/ungültiges Padding / text variants | Ablehnung inkl. nichtkanonischer Pad-Bits / reject incl. noncanonical pad bits | #39 | reference |
| R14 | Testmatrix und lokale Doku-Links / catalogue and local links | eindeutige IDs, gültige Phasen/Status, kein fehlendes Ziel / unique IDs, valid phase/status, no missing target | #39 | reference |
| C01 | P NFKC, F unverändert, Argon2 Secret/AD / normalized P, raw F | unabhängiger Argon2id-v0x13-Vektor mit echten Mindestparametern / independent vector at real minimum parameters | #40 | planned |
| C02 | B→W→C und C→Payload, alle Profile / all profiles | unabhängige HKDF/AES-GCM-Vektoren inkl. AAD, nicht nur Roundtrip / independent vectors including AAD | #40 | planned |
| C03 | alle 7 Schlüsselalgorithmen × 3 Profile / all algorithms/profiles | Seed unverändert, Public Key erneut abgeleitet / same seed, public key rederived | #40 | planned |
| C04 | Einzeldatei/Ordner, leer/1/65535/65536/65537/mehrere Blöcke / sizes and archive kinds | vollständiger Roundtrip, konstanter Speicher / complete roundtrip, bounded memory | #40 | planned |
| C05 | F fehlt/falsch/0/31/33/sehr groß / absent, wrong, sizes | höchstens 33 Bytes gelesen, keine Neuerzeugung / read at most 33, never recreate | #40 | planned |
| C06 | P/F/R jeweils falsch; R fehlt / wrong secrets, absent R | generisches Decrypt bei Auth-Fehler, fehlende Eingabe vor KDF / generic auth failure, missing input before KDF | #40 | planned |
| C07 | m/t/p min−1/min/max/max+1; Salt 15/16/64/65 / KDF boundaries | falsche Werte vor KDF/Allokation abgelehnt / reject before KDF/allocation | #40 | planned |
| C08 | jedes JSON-Feld unbekannt/doppelt/fehlend/null/falscher Typ / each field malformed | schemaabhängige Ablehnung, keine Panik / schema rejection, no panic | #40 | planned |
| C09 | Base64/Hex nichtkanonisch, NFC/Zeit/Public-Key-Länge falsch / invalid encodings and metadata | Ablehnung vor KDF / reject before KDF | #40 | planned |
| C10 | jedes Header-/Nonce-/Hüllen-/Tag-/Payload-Byte verändert / mutate each byte | Parser oder AEAD scheitert, kein Klartext publiziert / parsing or AEAD fails, no published plaintext | #40 | planned |
| C11 | Recovery entfernen/tauschen, Rollen/Profile/Provider/Policy ändern / altered protection | kein alternativer Pfad, Payload bindet unbenutzte Hülle / no alternate path, unused wrap authenticated | #40 | planned |
| C12 | Kürzen an jeder Headerposition, u32::MAX-Länge, Gesamtbudget / truncation and oversized lengths | begrenzter Parser, vor Allokation scheitern / bounded parser, fail before allocation | #40 | planned |
| C13 | STREAM-Blöcke tauschen/entfernen/anhängen, fehlende Endmarke / stream attacks | Authentifizierung scheitert, keine Teilausgabe / authentication fails, no partial publication | #40 | planned |
| C14 | v1 ohne/mit explizitem F; v2 ohne F / compatibility | Matrix in U0-1 exakt erfüllt / exactly follow compatibility table | #40 | planned |
| C15 | v1-Empfängerdatei + v2-Key für alle KEM-Sätze / recipient compatibility | F nur am privaten Key, v1-Datei bleibt v1 / factor on private key only | #40 | planned |
| C16 | v2→v1, unbekannte Version, v2 Empfänger, alte gültige Kopie / downgrade | Manipulation scheitert; alte gültige Kopie als bekannte Grenze / reject tampering, old valid copy is known limitation | #40 | planned |
| C17 | RNG-Fehler bei F/S/C/H/R/Q/Nonce/Challenge, Nonce-Kollision / each RNG stage | Abbruch ohne fertige Ausgabe; begrenztes Neuversuchen / no publication, bounded retry | #40 | planned |
| C18 | JSON-/Binary-Parser-Fuzzing, arithmetische Überläufe / fuzz and overflow | keine Panik, keine unbeschränkte Allokation / no panic or unbounded allocation | #40 | planned |
| T01 | TPM echte Probe, Seal/Load/Unseal und Neustart / real lifecycle | H identisch, Name/Attribute/Policy geprüft / identical H, validate name/attributes/policy | #40 | planned |
| T02 | TPM fehlt/Rechte/unsupported/busy/Timeout / device errors | eindeutige Ursache, kein file-Fallback / clear cause, no file fallback | #40 | planned |
| T03 | fremdes TPM/Reset/Blob- oder Parent-Name-Manipulation / wrong/reset/tampered TPM | normal scheitert, explizites P/F/R weiterhin möglich / normal fails, explicit recovery remains possible | #40 | planned |
| T04 | Fehler in Probe/Seal/Load/Unseal/Cleanup / each failure stage | keine geleakten Sessions/Handles; Cleanup-Fehler sichtbar / no leaks, cleanup error visible | #40 | planned |
| T05 | Linux/Windows echte Hardware, OS-Update ohne PCR-Bindung / platform parity | gleicher Vertrag, erneutes Öffnen / same contract, reopen succeeds | #40 | planned |
| F01 | einmal enroll, zweimal derive, reconnect/frische Challenge / enrollment repeatability | gleiches T, UP/UV und Signatur geprüft / same T, validated UP/UV/signature | #40 | planned |
| F02 | kein Token/anderer Token/Reset/Credential fehlt/Kapazität voll / unavailable token cases | Fehler ohne Fallback, kein unnötiges enroll / fail without fallback or extra enrollment | #40 | planned |
| F03 | falsche/gesperrte PIN, UV/UP abgelehnt, Abbruch/Timeout / user verification failures | keine Ausgabe, kein stiller Retry / no output or silent retry | #40 | planned |
| F04 | PRF fehlt/0/31/33/64 Bytes, UV=0, falsches Q / invalid PRF results | nie akzeptieren oder abschneiden / never accept or truncate | #40 | planned |
| F05 | RP-ID/Credential/Prüfschlüssel/Challenge/Signatur manipuliert / assertion attacks | Anbieter verweigert T vor Core / provider rejects before returning T | #40 | planned |
| F06 | raw CTAP gegen WebAuthn-PRF, UV/non-UV / semantic mismatch | Kennungen nicht austauschbar / no provider aliasing | #40 | planned |
| F07 | BE/BS, Softwaretoken, unbewiesene Hardwareherkunft / provenance cases | Hardware-Zusage verweigern / reject hardware guarantee | #40 | planned |
| F08 | Linux/Windows echte Token, Null-Signaturzähler / real platform checks | verifizierter Vertrag; Nullzähler allein kein Fehler / verified contract; zero counter alone allowed | #40 | planned |
| F09 | Abbruch nach Registrierung / cancel after enrollment | zurückbleibendes Credential melden, keine falsche Löschzusage / report residue honestly | #40 | planned |
| W01 | Hardware-Recovery auf frischem Rechner ohne Gerät / offline recovery | P/F/R genügt, null Hardwareaufrufe / P/F/R sufficient, zero hardware calls | #40 | planned |
| W02 | exportiertes R nicht lesbar/falsch/nicht bestätigt / recovery export failures | kein fertiger Container / no finished container | #40 | planned |
| W03 | Migration aller Profile in alle Profile / all profile migrations | vollständige Authentifizierung, frisches Material, alter Container unverändert / full authentication, fresh material, old unchanged | #40 | planned |
| W04 | Fehler nach jedem Einrichtungsschritt, Platte voll, Ziel vorhanden / failures at each step | kein Überschreiben, keine veröffentlichte Teilausgabe / no overwrite or partial publication | #40 | planned |
| W05 | verlorenes F/vergessenes P/alte Kopien / loss scenarios | keine erfundene Recovery, alte Kopien nicht widerrufen / no invented recovery or revocation | #40 | planned |
| U01 | CLI/Menü alle Profile, DE/EN, explizite Recovery / UX paths | eindeutige Auswahl, kein impliziter Wechsel / explicit choice, no implicit switch | #41 | planned |
| U02 | neue Einrichtung ohne Hardware interaktiv/nichtinteraktiv / unsupported setup | Bestätigung für file, required scheitert / confirm file, required fails | #41 | planned |
| U03 | F/R FIFO/Gerät/Symlink/Reparse, Pfadwechsel nach Prüfung / file attacks | regulären Handle prüfen, nicht blockieren/folgen / verify regular handle, no blocking/following | #41 | planned |
| U04 | F/R-Rechte Linux/Windows zu breit, ACL-Fehler / permissions failures | keine neue unsichere Veröffentlichung / no insecure new publication | #41 | planned |
| U05 | argv/Umgebung/Logs/Debug/API mit Marker-Geheimnissen / secret channels | keine Offenlegung, API lehnt alle Faktorprofile ab / no disclosure, API rejects factor profiles | #41 | planned |
| U06 | Landlock/Seccomp erlaubte/verbotene Pfade/Geräte/IPC / sandbox boundaries | normale Abläufe möglich, fremde Zugriffe gesperrt / normal works, unrelated access denied | #41 | planned |
| U07 | temporäre Klartextdateien bei Fehlern/Abbruch / temporary plaintext | Aufräumen, keine Erfolgsmeldung bei Cleanup-Fehler / cleanup, no false success | #41 | planned |
| S01 | Simulator-ID im Produktionscontainer / simulator in production | unsupported vor Prozessstart / before process launch | simulator | planned |
| S02 | überlange/abgeschnittene Nachrichten, Hänger, fremde Operation / IPC attacks | begrenzt ablehnen, Timeout, keine Shell / bounded rejection, timeout, no shell | simulator | planned |
| S03 | jeder T/F-Fehler injizierbar / inject every T/F error | gleicher Fehlervertrag, keine Hardware-Sicherheitsbehauptung / same error contract, no hardware claim | simulator | planned |

## Ausführung / Execution

DE: R11-Sollwerte wurden am 08.11.2026 unabhängig mit dem bereits vorhandenen
Python-Paket cryptography 41.0.7 (`HKDF`, `SHA3_256`) berechnet; die ausgeführten
Tests nutzen nur hashlib/hmac aus der Standardbibliothek. Öffentliche KAT-Bytes:
B=0..31, S=32..63, H=64..95, T=96..127, R=128..159. Info gemäß U0-1,
Ausgabelänge 32. R10 prüft dieselbe Referenzfunktion gegen
[RFC 5869 Fall 1](https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1).
Es werden keine echten Geheimnisse oder verschlüsselten Container eingecheckt.
EN: R11 expected values were independently computed on 2026-11-08 using the
already installed cryptography 41.0.7 (`HKDF`, `SHA3_256`); tests use only standard
hashlib/hmac. Public KAT bytes: B=0..31, S=32..63, H=64..95, T=96..127, R=128..159;
info per U0-1, output length 32. R10 checks the same reference function against
RFC 5869 case 1. No real secrets or encrypted containers are committed.

```sh
python3 -m unittest discover -s scripts -p 'test_factor_spec*.py' -v
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --no-default-features --locked -- -D warnings
cargo test --locked
bash scripts/check_limits.sh
cargo deny check
```

DE: Rust-Prüfungen sind Regressionstests von v1, keine v2-Abnahme. Hardwaretests
brauchen getrennte Linux-/Windows-Nachweise; Simulator oder Cross-Compile genügt
nicht. Für die Folge-PRs jeder ID konkrete Testnamen/Plattform zuordnen und den
Status erst nach tatsächlicher Ausführung ändern. Für #39 fehlen weiterhin
unabhängige Argon2-Secret/AD- und AES-GCM-Gesamtvektoren sowie Anbieterreview.
EN: Rust checks are v1 regression tests, not v2 acceptance. Hardware tests require
separate Linux/Windows evidence; simulators or cross-compilation do not suffice.
Follow-up PRs must map each ID to test names/platforms and change status only after
actual execution. #39 still needs independent Argon2 secret/AD and complete
AES-GCM vectors and provider review.
