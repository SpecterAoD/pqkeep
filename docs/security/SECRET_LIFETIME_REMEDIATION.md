# Remediation proposal / Behebungsvorschlag (#147)

DE: Konkreter Folgeplan zum [Auditregister](SECRET_LIFETIME_AUDIT.md). Dieser Audit-PR
ändert keine produktiven Speicherpfade und autorisiert keine nachfolgende Implementierung,
Systemänderung oder Veröffentlichung. Prioritäten betreffen die Reihenfolge der Nacharbeit.
Jeder Schritt benötigt einen freigegebenen engen Plan und einen unabhängig prüfbaren PR.
EN: Proposed follow-up only, not runtime implementation/authorization. Keep independent
reviewable steps with prior approval; no system/release changes implied by audit completion.

## R1 — eliminate payload staging / zusätzliche Nutzinhaltpuffer entfernen

DE: A1/A4, zuerst. Dateien: `src/files/encrypt.rs`, `decrypt.rs`, `src/sign/hash.rs` und
eigene Regressionstests. Archiv-/STREAM-Reader haben bereits gesperrte Chunk-Puffer: rohe
Dateihandles direkt damit verbinden statt sie zusätzlich in std-Puffer zu kapseln.
Den Signatur-Eingabepuffer durch vorab gesperrte SecretBytes ersetzen. Keine Änderung an
Hashalgorithmus, Dateiformat, atomarem Publish, Quelländerungsprüfung oder Dateirechten.
EN: Reuse existing locked chunks and direct file I/O; lock the detached-hash input buffer.
Do not replace buffering on ciphertext paths just because the type name matches.

DE: Prüfen: 0/1 Byte, Standardpuffergrenze ±1, 64-KiB-Grenze ±1, kleine letzte Blöcke,
mehrere Dateien; kurze Reads, Interrupted, Lese-/Schreibfehler, Sync-/Publishfehler, verweigerte
Sperre. Vor jeder Secret-Verarbeitung müssen alle vorgesehenen Puffer gesperrt sein. Keine
Teilausgabe publizieren. Wipe vor Unlock bei normalem Fehler/Drop/Unwind beobachten, niemals
freigegebenen Speicher lesen. Vorher rot/nachher grün am echten Anwendungspfad nachweisen.
EN: Add real-path ownership/lock tests and failure/tamper/atomicity regression, not merely a
type-name assertion or the std-fixture reproducer. Crash/abort remains a separate boundary.

## R2 — in-place AEAD / AEAD ohne ungeschützte Vorabkopie

DE: A2. Dateien: `src/crypto/aead.rs`, `stream.rs`, neue Adapter-/KAT-/Fehlertests. Vorab
gesperrten Arbeitsbereich benutzen und die vorhandene Provider-Operation `AeadInOut`
mit abgesetztem Tag aufrufen. Klartext erst in gesperrten Speicher kopieren; normale
Ciphertext-Vec erst nach vollständiger Verschlüsselung bilden. Tagposition, Nonce, AAD,
Zähler und Bytes aller bisherigen Seed-/Key-/STREAM-Verträge unverändert erhalten.
EN: Use existing reviewed in-place primitives, not new crypto. A public output allocation
is safe only after every byte it receives is ciphertext. Preserve wire bytes and KATs.

DE: Prüfen: leere Eingabe, Seeds/Filekeys und Chunkgrenzen; Auth-/Schlüssel-/Noncefehler,
Lock-/Allokationsverweigerung, Fehler während der Operation. Geheimnisse bei Fehler nicht
in einen normalen Vec retten. Kein stiller Rückfall auf den allokierenden Komfortaufruf.
EN: Lock denial must precede private copying/processing; on failure wipe guarded storage.
Prove destination ownership while the backend is live; never inspect freed allocations.

## R3 — rekey framing / Rekey-Framing in gesperrter Eingabe

DE: A3. Dateien: `src/cli/rekey_input.rs`, `secret_input.rs`, Rekey-/Mehrzeilen-/Pipe-Tests.
Vorhandene direkte OS-Handle-Leser und SecretBytes wiederverwenden. Alte/neue Passphrase,
Bestätigung und Extra-Byte vor dem Lesen sperren; keine stdin-Read-ahead-Schicht.
Bestehenden Vertrag für drei begrenzte Zeilen plus EOF, CRLF, Mindeststärke und Bestätigung
genau erhalten. Das bisherige Byte-Limit zählt den Zeilenabschluss mit; Grenzfälle explizit
prüfen, nicht nebenbei auf andere Semantik umstellen.
EN: Preserve framing and raw limits while replacing wipe-only/read-ahead storage. Test exact
limits, missing/extra newline/data, mismatch, invalid UTF-8, read/lock failure and early exit.

## R4 — HTTP ownership / HTTP-Ownership zuerst klären

DE: A5 und eingehender Teil von A6. Dateien: API-Request-Typen, Body-/Header-/Parsergrenze,
Serveradapter und in-process Request-/Abbruchtests. Nicht nur `String` nach dem Parsen sperren:
Transport, Parser-Scratch, Teil-Deserialisierung, frühe Validierung, Blocking-Queue und Task-
Abbruch sind Teil des Datenflusses. Vor Secret-Eingang begrenzen/reservieren/sperren; aus
einem späteren Guard keinen rückwirkenden Schutz der Frameworkpuffer ableiten.
EN: An ownership/transport ADR must precede claiming complete ingress protection. Use existing
libraries where they can satisfy the contract; source-review pinned internals, no custom crypto.

DE: Wenn der vorhandene Stack den strengen Vertrag nicht belegbar erfüllen kann, braucht es
eine ausdrückliche Entscheidung über einen sicheren Adapter oder eine sichtbar verweigerte
Secret-Operation. Kein versteckter ungesperrter Fallback, keine unbemerkte Abschaltung und
keine Behauptung, Token-Auth/Bodylimit löse das Speicherproblem. API-Kompatibilität mit #98
abgleichen; neue Protokolle/Netzwerkfreigaben nicht in den Audit hineinziehen.
EN: Make incompatible safety decisions explicit and reviewed; do not silently accept unsafe
ingress or secretly disable an interface. Test parse errors, unknown fields, limits, timeout,
disconnect, cancellation, queue pressure, failed lock and sanitized responses.

## R5 — token construction / gesperrte Token-Konstruktion

DE: A6, Erzeugung. Dateien: `src/api/token.rs`, CLI-Displayadapter, Token-/Format-/Fehlertests.
Vorhandene RNG-/SecretBytes- und Base64-in-place-APIs verwenden; feste vorab gesperrte
Kapazität für Rohbytes, Präfix und Text. Keine `encode_string`-/`format!`-Zwischenkopie.
Hashdatei und Format `pqk1_` bytekompatibel erhalten. Secret-Text nicht als frei klonbaren
String zurückgeben; bewusstes einmaliges Anzeigen und Caller-Ownership separat dokumentieren.
EN: Bound/lock before construction, preserve token entropy/encoding/hash format, handle write/
lock failures without output. Coordinate return-type changes with #98. Header ingress stays R4.

## R6 — provider lifetime / Provider-Lebensdauer

DE: A7. Dateien: KEM-/DSA-/AES-Adapter, konkrete Provider-/Cargo-Pins erst nach Prüfung;
Argon2-/SHA3-/Unicode-Interna im Inventar nicht als voll auditiert markieren. Typisierte
Seeds, expandierte private Zustände und Konstruktortransfers einzeln kartieren. Vorhandene
gesperrte Zustände/Zeroize-Provider weiterverwenden; nötige In-place-Konstruktoren gezielt
mit Herkunft, Lizenz und Gegenproben bewerten. Keine neue Kryptoimplementierung oder beliebige
Providerinjektion. Algorithmus-/Providerinventar #216 nicht duplizieren.
EN: Separate app-controlled typed construction from unavoidable compiler/register and OS
limits. A stable locked destination alone is not proof of copy-free construction. Never
promise elimination of every register copy. Unsupported secret processing must fail closed.

DE: Prüfen: alle vorhandenen KEM-/DSA-Parametersätze und KATs, Wrapping v1/v2, Signaturen v3,
fehlende Ressourcen, teilinitialisierte Zustände und Wipe-before-Unlock. Keine abgesenkten
KDF-/Krypto-Parameter oder Wiederverwendung alter Schlüssel als Ressourcen-Workaround.
EN: Require compatibility and source/lifetime evidence; return a sanitized failure instead
of processing in unprotected storage. Any vendor patch remains narrowly scoped and reviewed.

## R7 — process/GUI policy / Prozess-/GUI-Policy

DE: A8 mit #128/#149/#150. Dateien: Prozesshärtung, CLI/serve-Gates und dokumentierter
Embedder-/Helper-Vertrag. Erfolgreiche Linux-Flags, fehlschlagende Syscalls und Windows-
Fähigkeiten unterscheiden. Einen zwingenden Sicherheits-Gate vor Secret-Verarbeitung planen;
Bibliotheken dürfen den gesamten Hostprozess nicht unerwartet einschränken. Externe Dialoge
halten eigene Widgets/.NET-Strings; die Rust-Elternsperre schützt sie nicht.
EN: Review a strict capability/policy gate and host/helper responsibility before changing
behavior. A Windows false/false report is not a completed hardening guarantee. Test denial,
child cancellation/pipe closure and fresh child startup, without leaking secrets to arguments.

DE: WER-/Dump-/Debugger-/ACL- und Systemrichtlinien bleiben konkrete Deploymententscheidungen
mit gesonderter Freigabe. Keine automatische Registry-Löschung, Privilegienausweitung oder
Änderung von Swap/Ruhezustand. Messungen und vorgeschlagene Regeln sind keine geprüfte
Konfiguration aller Nutzerrechner. OS-/Stromverlustgarantien nicht aus Cleanup-Tests ableiten.
EN: Never disable controls to run a test or present operational advice as verified deployment.

## R8 — metadata classification / Metadaten klassifizieren

DE: A9 mit #98/#117: Archivnamen/Listen sind bewusst vertrauliche Ausgaben, keine automatisch
öffentlichen Daten. Benötigte Retention, Debug/Clone-/Serialisierungs- und Lock-/Wipe-Regeln
vor der API-Stabilisierung festlegen. Bestehende List-only-Limits und vollständige Authentisierung
vor Ausgabe erhalten. Keine globale JSON-/Pfadtypänderung ohne gesonderten Kompatibilitätsplan.
EN: Define a reviewed confidential-metadata contract; preserve current authenticated listing
and opt-in disclosure. A key-material wrapper alone does not settle metadata policy.

## Release gates and rollback / Abnahme und Rückweg

DE: Für jede Laufzeitnacharbeit: fmt, beide Clippy-/Feature-Konfigurationen, echte native
Linux-/Windows-Positiv-/Negativ-/Grenztests, alte Schlüssel/Archive v1/v2/v3, keine Teilausgabe,
keine Secret-Logs und konkrete Lock-/Wipe-Beobachtung. Fuzz/Crash-/Providerprüfungen nur
entsprechend geändertem Pfad erweitern; vorhandene Matrixbelege nicht pauschal hochstufen.
EN: Report source, fixture, actual-path, platform and external evidence separately. Passing
functional CI is not a proof that every memory copy is locked.

DE: Jeder Nacharbeits-PR muss separat rücknehmbar sein. Rückweg vorab praktisch auf den
genauen Basisbaum prüfen; keine Datenmigration. Ein Revert, der strengere Secret-Sperren
entfernt, ist eine Sicherheitsrücknahme und keine automatische Reaktion auf knappe Ressourcen.
Der Revert dieses Audit-PRs entfernt nur Doku/Proben; #148/#186 bleiben erhalten.
EN: Reviewed explicit revert only; never silently weaken memory protection. Preserve user
archives/keys and verify compatibility instead of converting them during security rollback.
