# U0-1: Anbieterreview / Provider review

DE: Recherche vom 08.11.2026; **keine Abhängigkeit ausgewählt oder installiert**.
Die folgende Bewertung trennt dokumentierte Schnittstellen von nicht erbrachten
Plattformnachweisen. Gates P1–P5 müssen vor Hardware-Core-Code entschieden sein.
EN: Research dated 2026-11-08; **no dependency selected or installed**. Distinguish
documented interfaces from outstanding platform evidence. Resolve gates P1–P5
before hardware core implementation.

## Kandidaten und Quellen / Candidates and sources

| Kandidat / Candidate | Befund / Evidence | Entscheidung / Decision |
|---|---|---|
| [tss-esapi 7.7.0](https://docs.rs/crate/tss-esapi/7.7.0), [Upstream](https://github.com/parallaxsecond/rust-tss-esapi) | Apache-2.0; Rust-Wrapper um native TSS2/ESAPI, kein reines Rust-TPM / Rust wrapper around native TSS2/ESAPI, not pure Rust TPM | Linux-Kandidat; Windows-Gleichheit nicht nachgewiesen / Linux candidate; Windows equivalence unproven |
| [Windows TBS](https://learn.microsoft.com/en-us/windows/win32/tbs/tpm-base-services-portal) | Systemdienst/API für TPM-Zugriff / system service/API for TPM access | Kein Beleg für sichere Rust-Seal/Unseal-Abstraktion; CNG-Schlüsselspeicher nicht ungeprüft gleichsetzen / no proof of safe Rust sealing abstraction; do not assume CNG equivalence |
| [libfido2 1.17.0](https://github.com/Yubico/libfido2), [NEWS](https://github.com/Yubico/libfido2/blob/main/NEWS) | BSD-2-Clause; Linux/Windows, native Bibliothek; Release behebt u.a. DLL-Suchpfadproblem YSA-2026-01 / native library; release includes DLL search-path fix | Fähigkeiten geeignet zur weiteren Prüfung; sichere Rust-Bindings samt Transitiven prüfen / candidate capabilities; audit safe Rust bindings and transitives |
| [libfido2 Rust-Binding](https://github.com/PvdBerg1998/libfido2/blob/master/Cargo.toml) | Manifest 0.1.0, lokales libfido2_sys mit Veröffentlichungs-TODO / manifest 0.1.0, local libfido2_sys with publishing TODO | Kein nachgewiesener crates.io-only-Abhängigkeitspfad / no proven crates.io-only dependency path |
| [authenticator-rs](https://github.com/mozilla/authenticator-rs/blob/ctap2-2021/Cargo.toml) | Upstream-Manifest 0.6.2, MPL-2.0; docs.rs-Snapshot zeigte 0.5.0 / upstream manifest 0.6.2, docs.rs snapshot showed 0.5.0 | MPL-2.0 fehlt in deny.toml; keine stillschweigende Lizenzfreigabe, kein Pin anhand Suchindex / not allowlisted; no implicit licence approval or search-index version pin |

DE: tss-esapi-Release 7.7.0 und 8.0.0-alpha.4 sind auf docs.rs datiert; Alpha nicht
automatisch bevorzugen. Vor #40 exakte veröffentlichte Version, MSRV, Lizenzbaum,
RustSec und native Hersteller-Advisories erneut gegen einen konkreten Lockfile-Plan
prüfen. Die RustSec-Paketabfragen dieser Recherche lieferten keine verwertbare
Paketliste; daraus folgt **keine** Aussage „keine Advisories“. Keine Bibliothek
wurde hier gebaut oder mit Hardware getestet.
EN: docs.rs dates releases 7.7.0 and 8.0.0-alpha.4; do not automatically prefer
alpha. Before #40 recheck exact published version, MSRV, licence tree, RustSec
and native vendor advisories against a concrete lockfile plan. RustSec package
queries in this research returned no usable package list; this is **not** a
clean advisory report. No library was built or tested with hardware here.

## P1: TPM-Policy und Plattformgleichheit / TPM policy and platform parity

DE: Ziel ist ein nicht migrierbarer Parent und versiegeltes 32-Byte-H, beide
`fixedTPM`/`fixedParent`, keine PCR-Bindung. Vorschlag für Review: deterministisch
wiederherstellbarer Primary unter Owner-Hierarchie, dessen Name gespeichert und
beim Öffnen geprüft wird; kein global fest reservierter persistenter Handle.
Primary-Template, Hash-/Symmetrieparameter, Kind-Attribute, Autorisierung und
verschlüsselte Sessions benötigen bytegenaue TCG-Prüfung. Keine Änderung an
Owner-Auth, Provisionierung oder TPM-Reset durch PQKeep. Unzugängliche Hierarchie
ist unsupported. Keine exportierte Ersatzschlüsseldatei für H.
EN: Target a non-migratable parent and sealed 32-byte H, both fixedTPM/fixedParent,
without PCR binding. Review proposal: reproducible owner-hierarchy primary with
stored/verified name, no globally reserved persistent handle. Primary template,
hash/symmetric parameters, child attributes, authorization and encrypted sessions
need byte-exact TCG review. PQKeep must not change owner auth, provision or reset
the TPM. Inaccessible hierarchy means unsupported. No exported substitute key for H.

DE: Abschlussnachweis: gleicher Vertrag auf Linux/Windows; echtes Create/Seal/Load/
Unseal, Wiederöffnung nach Prozessneustart und OS-Update, Abweisung fremdes TPM,
Reset, falscher Name/Blob, Rechte und Busy. Aufräumen jeder Session/jedes transienten
Objekts auch nach Fehler. Diese Nachweise fehlen; TPM-Policy 1 ist nicht freigegeben.
EN: Evidence required: same Linux/Windows contract; real create/seal/load/unseal,
reopen after process restart and OS update; reject other TPM, reset, wrong name/blob,
permissions and busy. Clean every session/transient object on failures too.
Evidence is outstanding; TPM policy 1 is not approved.

## P2: FIDO2-Auswertung und Prüfung / FIDO2 evaluation and verification

DE: Provider 2 nutzt direkt CTAP2 hmac-secret mit Q, nicht WebAuthn eval.first.
[WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension) hasht seinen Input
mit festem Präfix. [CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension)
unterscheidet zudem PRFs mit/ohne UV. Daher UV bei Einrichtung und jedem Öffnen
erzwingen; nicht nur das Vorhandensein eines 32-Byte-Ergebnisses prüfen.
EN: Provider 2 uses direct CTAP2 hmac-secret with Q, not WebAuthn eval.first.
WebAuthn PRF hashes its input with a fixed prefix; CTAP distinguishes UV and
non-UV PRFs. Require UV during setup and every opening, not just a 32-byte output.

DE: Registrierung einmal je Container, bevorzugt nicht discoverable, ES256,
hmac-secret, UP/UV. Lokale zufällige User-ID ohne Personendaten. Anschließend
zwei Auswertungen mit frischen Challenges, dazwischen Verbindung neu öffnen;
T zeitkonstant vergleichen. Kein T aus Signaturbytes ableiten. Der geprüfte
Anbieter muss Challenge/ClientData-Hash, RP-ID-Hash, Credential-ID, Signatur,
UP/UV und Erweiterung prüfen, bevor T an Core gelangt. PIN nur verdeckt im
Speicher, Protokoll und Fehlerbehandlung durch die Bibliothek, keine PIN-Cache-
Umgehung der geforderten Verifikation. Signaturzähler ist ohne externen Zustand
kein Rollbackschutz und darf bei zulässigem Nullzähler nicht allein sperren.
EN: Enroll once per container, preferably non-discoverable, ES256, hmac-secret,
UP/UV, random local user ID without personal data. Evaluate twice using fresh
challenges and reconnect between attempts; compare T in constant time. Never
derive T from signature bytes. The reviewed provider must validate challenge/
client-data hash, RP-ID hash, credential ID, signature, UP/UV and extension before
returning T. PIN only in hidden input/memory, library-managed protocol/errors;
no cached-PIN bypass of required verification. Without external state, signature
counters do not prevent rollback; a permitted zero counter alone must not block.

DE: [libfido2 Assertion-Prüfung](https://developers.yubico.com/libfido2/Manuals/fido_assert_verify.html)
und [HMAC-Salt-Schnittstelle](https://developers.yubico.com/libfido2/Manuals/fido_assert_set_hmac_salt.html)
sind Prüfansatzpunkte, kein Beweis, dass vorhandene Rust-Bindings alle Checks
erzwingen. RP-ID `pqkeep.local` ist ein nativer Anwendungskontext, keine Website
und kein DNS-Zugriff; Eignung für ausgewählte Windows-Anbindung testen.
EN: libfido2 assertion verification and HMAC-salt APIs are review starting points,
not proof that existing Rust bindings enforce every check. `pqkeep.local` is a
native application context, not a website or DNS request; test suitability for
the selected Windows integration.

## P3: Hardwareherkunft / Hardware provenance

DE: BE=0/BS=0 und ein behaupteter Modellname genügen allein nicht zum Beweis
hardwaregebundener Geheimnisse. Benötigt wird eine dokumentierte lokale
Vertrauenskette/Modellfreigabe einschließlich Prüfung der Attestation, falls diese
den Nachweis trägt. Keine automatische Online-Metadatenabfrage. Geräte ohne
belastbaren Nachweis bleiben unsupported für das Hardware-Schutzversprechen;
keine neue Software-FIDO2-Alternative still einführen. Vertrauen, Aktualisierung
und Widerruf dieser lokalen Informationen sind vor Umsetzung zu entscheiden.
EN: BE=0/BS=0 and an asserted model name alone do not prove hardware-bound secrets.
Define a local trust chain/model policy and attestation validation where relied
upon. No automatic online metadata lookup. Devices without sufficient evidence
remain unsupported for the hardware guarantee; do not silently add a software
FIDO2 alternative. Decide trust, updating and revocation of local evidence before implementation.

## P4: Rechte und Sandbox / Permissions and sandbox

DE: Dateifaktor-/Recovery-Handles gegen Symlink-/Reparse-Austausch absichern;
Windows-Benutzer-ACL ohne eigenen unsafe-Code nachweisen. Landlock nur gewählte
Dateien/Geräte; Seccomp aus echten Aufrufen ableiten. TPM-/USB-Aufrufe und lokale
System-IPC separat bewerten. Kein pauschales --no-sandbox, keine neuen ausgehenden
Netzwerkverbindungen, kein udev-/Gruppen-/Dienstumbau durch automatische Einrichtung.
EN: Protect factor/recovery handles against symlink/reparse substitution; prove
Windows user ACL handling without own unsafe. Grant only selected files/devices
in Landlock; derive seccomp from real calls. Review TPM/USB and local system IPC
separately. No blanket --no-sandbox, outgoing network, or automatic udev/group/service changes.

## P5: Simulator und Ressourcen / Simulator and resources

DE: Separater Schritt: probe/seal/unseal/cleanup sowie enroll/derive über begrenzte
Pipes; feste Nachrichten, Framing, Timeouts und Maximalgrößen vor Implementierung.
Keine Shell oder frei wählbaren Befehle. Simulator-Kennung niemals als echte
Hardware akzeptieren. Fehler bei Cleanup melden; ursprünglichen Fehler bewahren.
Token-Credentials können bei Abbruch zurückbleiben; nicht behaupten, sie immer
löschen zu können. Keine endlosen Busy-/PIN-Wiederholungen; Abbruch und Timeout testen.
EN: Separate step: probe/seal/unseal/cleanup plus enroll/derive over bounded pipes;
define messages, framing, timeouts and size caps before implementation. No shell
or arbitrary commands. Never accept simulator IDs as hardware. Report cleanup
failures without losing the original error. Token credentials may remain after
cancellation; never promise universal deletion. No endless busy/PIN retries;
test cancellation and timeout.
