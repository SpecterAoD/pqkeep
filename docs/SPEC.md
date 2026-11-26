# MASTER-PROJEKT-SPEZIFIKATION v2.22: PQKeep (Core, CLI & API)

> **English translation:** [`SPEC.en.md`](SPEC.en.md) – beide Fassungen werden im selben Pull Request gemeinsam geändert; bei Widersprüchen gilt bis zur Korrektur die deutsche. / Both versions are changed together in the same pull request; in case of contradiction the German one applies until fixed.

> Änderung v2.19 (22.11.2026, Eigentümerauftrag zur autonomen Sicherheitsbehebung bis main): Secret-Speicher einschließlich KDF-/HKDF-Arbeitspuffern zwingend sperren; Fehler statt ungesperrtem Fallback, begrenzte Eingaben und sichere Freigabe. Keine Änderung von Format-/Ableitungsbytes. Details: [LOCKED_SECRETS.md](security/LOCKED_SECRETS.md).

> Änderung v2.20 (24.11.2026, freigegeben von SpecterAoD): neues geplantes Update **U5 Privatsphäre und Metadaten** (Abschnitt 9) – zufällige äußere Dateinamen, Padding, anonyme Empfänger (optionale Ausnahme von D1), verborgener Absender, verschlüsselte Zeitstempel und erweiterte Attribute; alles optional und konfigurierbar, Standard aus; Abschnitt 4a entsprechend ergänzt (#315, #316, #123).

> Änderung v2.21 (25.11.2026, Auftrag SpecterAoD: #315/#316 bis zum Merge): **Formatentwurf v4** ([V4_DRAFT.md](V4_DRAFT.md)) für Padding, anonyme Empfänger (**D1-Ausnahme nur auf Wunsch, D1 bleibt Standard**), verborgenen Absender und den Strom-Modus (#83) – ein Versionsschema mit Optionsbits, Inhaltstyp „Strom“, Abschluss-Block im verschlüsselten Strom, Schlüsselbindung in jeder v4-Datei; nur Entwurf, Umsetzung in eigenen PRs vor #98 (#316, #83).

> Änderung v2.22 (26.11.2026, freigegeben von SpecterAoD): Speichersperre bleibt zwingend; weil das übliche `ulimit -l` (8 MiB) für den Argon2id-Puffer (256 MiB–1 GiB) nicht reicht, gibt das **Debian-Paket nur `/usr/bin/pqkeep` die Fähigkeit `CAP_IPC_LOCK`** (nur „permitted“, beim Start wirksam gemacht; postinst, `libcap2-bin`); das Programm selbst erhöht weiterhin weder Limits noch Rechte und meldet ein zu kleines Budget verständlich mit Abhilfe (#325, `docs/INSTALL.md`).

> Änderung v2.1 (06.11.2026, freigegeben von SpecterAoD): Datei- und Ordnerverschlüsselung (Abschnitt 4a, Schritt 3a).
> Änderung v2.2 (06.11.2026, freigegeben von SpecterAoD): Speicherhärtung (Schritt 2a), Build-Härtung (`panic = "abort"`, Prüfung PIE/RELRO/NX bzw. ASLR/DEP/CFG), wöchentliches Audit, Sandboxing (Schritt 5a), Root-Warnung (Schritt 4), Zeitausgleich für `/v1/validate` (Schritt 5).
> Änderung v2.3 (07.11.2026, freigegeben von SpecterAoD): geplante Updates nach der ersten Beta (Abschnitt 9): Signaturen, mehrere Empfänger, Einrichtungs-Assistent, Kontextmenü.
> Änderung v2.4 (07.11.2026, freigegeben von SpecterAoD): Wortlisten für die Passphrase-Prüfung (Schritt 2b), Ausnahme von 5c für die EFF-Wortlisten (CC BY 4.0).
> Änderung v2.5 (07.11.2026, freigegeben von SpecterAoD): Umbenennung von „PQC KeyForge“ in **PQKeep** (Crate, Bibliothek und Binary `pqkeep`, Repository `SpecterAoD/pqkeep`) wegen Namenskonflikt mit dem Kartenspiel „KeyForge“. Formatkennungen `PQKEEP-KEY`/`PQKEEP-PUB`, Domänentrennung `PQKeep/…`, Token-Präfix `pqk1_`; Endung `.pqkf` und `PQKFENC` bleiben. Vor dem ersten Release, daher ohne Kompatibilität zu Dateien des alten Namens.
> Änderung v2.6 (07.11.2026, freigegeben von SpecterAoD): Schritt 6 an die Umsetzung angeglichen – `main` per Ruleset ohne Pflicht-Review (ein Maintainer; Prüfung über Pflicht-Checks), offizieller SignPath-Wortlaut, Linux-Release-Build auf Ubuntu 22.04, Release zunächst als Entwurf, SignPath-Action erst nach Zusage, gitleaks als geprüftes Binary statt Action.
> Änderung v2.7 (08.11.2026, freigegeben von SpecterAoD): U1-1 präzisiert – Signaturformat `.pqsig` v1 (`docs/SIGNATURE_FORMAT.md`): nur ML-DSA-87, SHA3-512 und Dateigröße, Kontext-String `PQKeep/sig/v1`, signiert wird eine feste Binärkodierung statt JSON, Dateiname nicht signiert, Zeitstempel ist Angabe des Signierers.
> Änderung v2.8 (08.11.2026, freigegeben von SpecterAoD mit dem Merge von PR #79): Formatentwurf v2 für U0 und U2 gemeinsam (`docs/V2_DRAFT.md`, nicht implementiert): zweiter Faktor als Faktordatei mit genau 32 Zufallsbytes (Argon2id-Secret), mehrere Empfänger als Zugangsliste (höchstens ein Passphrase-Zugang + bis zu 64 ML-KEM-Empfänger), v2 nur wenn nötig; Entscheidungen D1–D4 (Empfänger-IDs sichtbar, Passphrase und Empfänger kombinierbar, v2 nur wenn nötig, Faktordatei mit zu offenen Rechten abgelehnt) am 09.11.2026 bestätigt; TPM/FIDO2 ausgelagert (#89), Nummern reserviert.
> Änderung v2.9 (09.11.2026, freigegeben von SpecterAoD): Mindeststärke neuer Passphrasen von 80 auf **128 Bit** angehoben (auch unter idealisiertem Grover-Angriff ohne Argon2-Schutz rechnerisch ≥ 64 Bit), wählbar bis 256 Bit (`--min-bits`); Generator standardmäßig 32 Zeichen, mindestens 24; Kurzform `pqkeep passphrase <länge>`. Bestehende Dateien bleiben lesbar (Prüfung nur beim Erstellen).
> Änderung v2.10 (09.11.2026, freigegeben von SpecterAoD): geführte Abläufe in der CLI (Schlüssel erstellen, Signieren, Prüfen) – im Menü oder wenn `generate`/`sign`/`verify` im Terminal ohne Pflichtangaben aufgerufen werden; nie ohne Terminal oder mit `--batch`. Sie fragen nur ab, zeigen die entsprechenden Befehle und starten diese als eigene Prozesse mit voller Sandbox (keine zweite Logik, keine Geheimnisse im Ablauf-Prozess).
> Änderung v2.11 (10.11.2026, freigegeben von SpecterAoD mit dem Plan zu #92): Kontextmenü auch für Thunar (Xfce) über die gemeinsame Datei `~/.config/Thunar/uca.xml` – nur eigene Blöcke mit festen Kennungen, fremde Aktionen bleiben Byte für Byte erhalten, strenge Aufbauprüfung ohne XML-Crate, Sicherung vor dem Schreiben, Prüfsumme je Block (Manifest Version 2).
> Änderung v2.12 (15.11.2026, freigegeben von SpecterAoD mit dem Projektplan „Community und Struktur“): englische Übersetzung `docs/SPEC.en.md`, gemeinsam gepflegt; externe Beiträge dürfen nur Englisch sein, die deutsche Fassung wird nachgezogen (`CONTRIBUTING.md`).
> Änderung v2.13 (16.11.2026, freigegeben von SpecterAoD): Ausnahme von 5c für Bilder der Dokumentation unter `docs/images/` (PNG, JPEG, WebP, höchstens 500 KB je Datei, Signatur passend zur Endung; geprüft von `scripts/check_limits.sh`).
> Änderung v2.14 (20.11.2026, freigegeben von SpecterAoD): wöchentliche Vorschau-Builds (Abschnitt 5, #269) – gleicher Build wie Releases, nur als unsigniertes GitHub-Pre-Release, im Programm als Vorschau gekennzeichnet; Betas und Releases bleiben unverändert.

> Änderung v2.15 (21.11.2026, eigentümerseitig freigegebener Plan zu #109): ausdrücklicher Passphrase-Wechsel privater Schlüsseldateien bei gleicher Identität/Format/Faktor, standardmäßig neue Ausgabe, bestätigter Austausch mit exakter verschlüsselter Sicherung, keine KDF-Absenkung. Siehe `docs/REKEY.md`.

> Arbeitsanweisung für Claude Code. Diese Spezifikation ist verbindlich. Bei Widersprüchen oder Lücken: nicht raten, sondern kurz nachfragen.

> Änderung v2.16 (21.11.2026, Freigabe zur Fertigstellung von PR #281): neue Vorschauen mit Keyless Sigstore, Build-/SBOM-Attestationen und Verifikation vor Veröffentlichung; kein SignPath oder Release-Environment, keine Änderung bestehender Vorschauen.

> Änderung v2.17 (21.11.2026, eigentümerseitig freigegebener Plan zu #117): authentisierte Archivliste ohne Extraktion; eigene JSON-Kennung und begrenzte Metadaten erst nach vollständiger Prüfung. Bestehende Formate/JSON-Befehle unverändert.

> Änderung v2.18 (21.11.2026, freigegeben von SpecterAoD mit dem Auftrag zu #44): optionale Absender-Signatur in `.pqkf` (U1) als Format **v3** – ML-DSA-87-Signatur über Header und Chiffrat am Dateiende, öffentlicher Schlüssel des Absenders und Schlüsselbindung im Header, Prüfung vor jeder Ausgabe, `--sign-with`/`--signer`; unsignierte Dateien bleiben v1/v2 Byte für Byte (`docs/V3_SIGNED.md`).

## 0. Arbeitsweise (gilt für jeden Schritt)

1. **Plan vor Code:** Vor jedem Schritt zuerst einen kurzen Plan (Dateien, Crates, Teststrategie) vorlegen und auf Freigabe warten.
2. **Ein Schritt nach dem anderen:** Erst wenn `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` und `cargo test` grün sind, gilt der Schritt als erledigt. Dann Zusammenfassung und erneut Freigabe abwarten.
3. **Recherche vor Crate-Wahl:** Aktuelle Versionen, Wartungsstatus und bekannte Advisories der Crates prüfen (docs.rs, RustSec). Keine Crates aus dem Gedächtnis einbinden, Versionen in `Cargo.lock` einfrieren.
4. **Ehrlichkeit:** Wo eine Anforderung technisch nur eingeschränkt erfüllbar ist (z. B. `zeroize`), das offen dokumentieren, nicht beschönigen.
5. **Commits:** Kleine, thematisch getrennte Commits pro Schritt.

## 1. Projekt-Ziel & Architektur-Prinzipien

Hochsichere, speichersichere, plattformübergreifende Anwendung (Windows & Linux) in reinem Rust zur **Generierung, Speicherung und Verwaltung** von Post-Quanten-Schlüsseln (ML-KEM, ML-DSA) und symmetrischen Schlüsseln (AES-256).

- **Keine Backdoors, minimale Angriffsfläche:** Strenge Eingabevalidierung (Länge, Zeichensatz, Format). Keine Telemetrie, **keine ausgehenden Netzwerkverbindungen**. Die API nimmt nur eingehende Verbindungen an.
- **Modulare Dateibeschränkung (angepasst):** Zweisprachige Kommentare verbrauchen viele Zeilen, daher gilt:
  - Produktionsdateien: max. **300 Zeilen** (physische Zeilen inkl. Kommentare und Leerzeilen).
  - Einzelne Funktionen: max. **50 Zeilen**.
  - Testdateien: max. **400 Zeilen**, ein Testthema pro Datei.
  - Wird eine Datei zu groß, in Untermodule aufteilen (z. B. `crypto/kem.rs`, `crypto/dsa.rs`, `crypto/kdf.rs`, `crypto/aead.rs`). Ein CI-Skript prüft alle Limits automatisch und lässt den Build bei Verstoß scheitern.
- **Tests grundsätzlich in eigenen Dateien:** Kein `#[cfg(test)] mod tests { ... }` mit Inhalt in Produktionsdateien. Tests der öffentlichen API liegen in `tests/*.rs`. Tests interner Funktionen liegen in einer eigenen Datei neben dem Modul (z. B. `src/crypto/kdf_tests.rs`), eingebunden nur per `#[cfg(test)] mod kdf_tests;` (eine Zeile). Das CI-Skript prüft, dass Produktionsdateien keine Testfunktionen (`#[test]`) enthalten.
- **Zweisprachigkeit:** Dokumentation, READMEs, Doc-Kommentare und Inline-Kommentare auf Deutsch **und** Englisch. Format: `// DE: ...` gefolgt von `// EN: ...`. Fehlermeldungen für Endnutzer (CLI) zweisprachig oder per `--lang de|en` wählbar. (Externe Beiträge dürfen nur Englisch sein; siehe `CONTRIBUTING.md`.)
- **Architektur:** Bibliothek (`lib.rs`) als Core, darauf aufbauend ein Binary (`main.rs`) mit CLI und API-Server. CLI und API nutzen ausschließlich die Core-API, keine duplizierte Kryptologik.
- **Fokus:** Zuerst Core, dann CLI, dann API. GUI ist ausdrücklich **nicht** Teil dieses Projekts (Non-Goal).
- **Begriff:** „Passkey“ in dieser Spezifikation meint eine **Passphrase** (Geheimnis des Nutzers), nicht WebAuthn/FIDO2-Passkeys. Im Code und in der Doku konsequent `passphrase` verwenden, um Verwechslungen zu vermeiden.

## 2. Bedrohungsmodell (kurz, in `docs/THREAT_MODEL.md` festhalten)

- **Schutzziel:** Vertraulichkeit und Integrität gespeicherter privater Schlüssel bei Verlust oder Diebstahl der Container-Datei (Offline-Angreifer).
- **In Scope:** Brute-Force auf die Passphrase, manipulierte Container-Dateien, fehlerhafte/bösartige Eingaben (CLI und API), Ressourcenerschöpfung (DoS) über die API.
- **Out of Scope:** Kompromittierter Host (Malware mit Speicherzugriff, Keylogger), Seitenkanäle auf Hardware-Ebene. Das wird in der Doku explizit genannt.

## 3. Sicherheits- & Performance-Anforderungen

### 3.1 Speichersicherheit
- `#![forbid(unsafe_code)]` im Projekt. Falls für Plattformfunktionen (z. B. Speicher-Locking) unvermeidbar: isoliert in einem einzigen, kommentierten Modul mit Begründung.
- Geheimnisse (private Schlüssel, Seeds, abgeleitete Schlüssel, Passphrase) in `Zeroizing<...>` bzw. Typen mit `ZeroizeOnDrop` / `secrecy`. Diese Typen implementieren **kein** `Debug`, `Display`, `Clone` oder `Serialize` mit Klartext-Ausgabe.
- Kein Logging von Geheimnissen oder Request-Bodies. Vergleich von Geheimnissen/Tags in konstanter Zeit (`subtle`).
- Doku-Hinweis: Zeroization ist „best effort“ (Kopien durch Compiler, Swap, Core Dumps). Secret-Speicherseiten einschließlich Argon2/HKDF müssen vollständig gesperrt sein, sonst Fehler. Core-Dump-/Compiler-/OS-Grenzen getrennt dokumentieren.
- Auditstand #147 (23.11.2026): Diese Anforderung ist kein Nachweis vollständiger Umsetzung.
  Offene I/O-/AEAD-/Rekey-/Signatur-/HTTP-/Tokenkopien und Plattformgrenzen sind im
  [Secret-Lebensdauer-Audit](security/SECRET_LIFETIME_AUDIT.md) mit Behebungsplan erfasst;
  der Audit-PR behebt keine produktiven Speicherpfade.

### 3.2 Kryptografie

DE: #147 R6-Kapselungsschritt: OS-Entropie, vollständige ML-KEM-G-Ausgabe K || r
und Ergebnis vor privater Befüllung in SecretBytes sperren; Provider liefert nur
öffentliches Chiffrat. Ableitungs-/Formatbytes bleiben gleich; Entkapselung,
Schlüsselaufbau und interne Provider-/Compilerkopien bleiben offene Auditarbeit.
Siehe [Plan](security/KEM_ENCAPSULATION_OWNER_PLAN.md); native Abnahme erforderlich.
- **Schlüsselaustausch:** ML-KEM (FIPS 203), Standard **ML-KEM-768**, wählbar ML-KEM-512/1024.
- **Signaturen:** ML-DSA (FIPS 204), Standard **ML-DSA-65**, wählbar ML-DSA-44/87.
- **Private Schlüssel** bevorzugt als kompakter **Seed** speichern und beim Laden neu ableiten (sofern die Crate das unterstützt), sonst als expandierter Schlüssel.
- **Symmetrische Schlüssel:** Erzeugung von AES-256-Schlüsseln (32 Byte) aus dem OS-CSPRNG (`getrandom`/`OsRng`).
- **Container-Verschlüsselung:** AES-256-GCM, 96-Bit-Nonce zufällig aus OS-CSPRNG, **pro Verschlüsselung neuer Salt und neuer Schlüssel**. Header und Metadaten werden als **AAD** mitauthentifiziert.
- **Schlüsselableitung:** Argon2id.
  - Parallelismus `p` = verfügbare CPU-Kerne (`available_parallelism`, nach oben begrenzt, z. B. max. 8).
  - **Wichtig:** `m`, `t`, `p` und Salt (≥ 16 Byte) werden im Container-Header gespeichert, damit die Entschlüsselung auf anderer Hardware funktioniert.
  - Untergrenzen beim Erzeugen (z. B. m ≥ 64 MiB, t ≥ 3), Obergrenzen beim Lesen fremder Container (z. B. m ≤ 1 GiB, t ≤ 10, p ≤ 16), um DoS über manipulierte Header zu verhindern.
  - Vordefinierte Profile (z. B. `standard`, `hardened`), Werte im Code zentral definiert.
- **Zufall:** Ausschließlich OS-CSPRNG. Kein `thread_rng`-Ersatz, keine eigenen Generatoren.
- **Krypto-Crates:** Bevorzugt gepflegte, reine Rust-Implementierungen (z. B. RustCrypto `ml-kem`, `ml-dsa`, `aes-gcm`, `argon2`, `zeroize`; alternativ `libcrux`). Auswahl begründen. Hinweis in der Doku: Die Crates sind nicht FIPS-140-validiert.

### 3.3 Passphrase-Sicherheit
- **Pflicht:** min. 16 Zeichen (Unicode-Zeichen zählen, nicht Bytes), Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen.
- **Zusätzlich:** Ablehnung von Wiederholungen/Sequenzen (`aaaa…`, `1234…`), kleiner eingebauter Blocklist-Check häufiger Muster, geschätzte Entropie mit Mindestwert **≥ 128 Bit** (seit v2.9; wählbar bis 256 Bit über `--min-bits`) und Rückmeldung, **warum** abgelehnt wurde.
- **Generator:** Kryptografisch sicher, **ohne Modulo-Bias** (Rejection Sampling), garantiert alle Zeichenklassen, Standard 32 Zeichen (≈ 210 Bit), mindestens 24 Zeichen (≥ 128 Bit auch ohne verwechselbare Zeichen). Optional: Wortlisten-Variante (Diceware, ≥ 6 Wörter). Entropie wird als `log2(Alphabetgröße) * Länge` berechnet und angezeigt.
- Eingabe nie über Kommandozeilenargumente oder Umgebungsvariablen, sondern nur über verdeckte Prompts, Stdin oder (API) Request-Body.

## 4. Container-Format (Basis für Schritt 3)

- JSON mit **Versionsfeld** (`format_version`) und Magic-/Typ-Feld. Binärdaten Base64 (Standard-Alphabet, strikt validiert).
- Klartext-Metadaten (authentifiziert als AAD): Name, Organisation, Firma, Abteilung, Account-Typ, Algorithmus-ID, Erstellungszeit (UTC), Schlüssel-ID (Fingerprint, z. B. SHA3-256 des öffentlichen Schlüssels), KDF-Parameter, Salt, Nonce.
- Verschlüsselter Teil: privater Schlüssel (bzw. Seed). Öffentlicher Schlüssel im Klartext.
- Hinweis in der Doku: Metadaten sind **nicht verschlüsselt** (personenbezogene Daten beachten).
- Parser: strenge Längen- und Zeichensatzgrenzen, `deny_unknown_fields`, maximale Dateigröße, keine Panics bei Fehleingaben.
- Keine Pfade im Container. Dateien werden **atomar** geschrieben (temporäre Datei, dann umbenennen), Linux-Rechte `0600`, unter Windows Ablage im Benutzerprofil.

## 4a. Datei- und Ordnerverschlüsselung (Basis für Schritt 3a)

- **Zweck:** Beliebige Einzeldateien und komplette Ordner (rekursiv) quantensicher ver- und entschlüsseln. Teil der Core-Bibliothek (`src/files/`, Kryptobausteine in `src/crypto/`), genutzt von der CLI. **Nicht** über die REST-API angeboten (Angriffsfläche und DoS-Risiko durch große Uploads).
- **Schlüsselmodi:**
  - *Passphrase:* Argon2id (Abschnitt 3.2, Parameter im Header) leitet den Schlüssel ab, der den Dateischlüssel einpackt.
  - *Empfänger:* ML-KEM (Standard ML-KEM-768) mit dem öffentlichen Schlüssel einer Person; gemeinsames Geheimnis → HKDF-SHA3-256 (Kontext: Header) → Schlüssel, der den Dateischlüssel einpackt. Zunächst genau **ein** Empfänger.
- **Dateischlüssel:** Pro Verschlüsselung ein neuer zufälliger 256-Bit-Schlüssel (OS-CSPRNG), eingepackt mit AES-256-GCM.
- **Inhalt:** Streaming-AEAD nach der STREAM-Konstruktion mit AES-256-GCM, Blockgröße 64 KiB, Nonce = Zufallspräfix ‖ Blockzähler ‖ Endmarke. Erkennt Kippen, Vertauschen, Entfernen, Abschneiden und Anhängen von Blöcken. Konstanter Speicherbedarf, unabhängig von der Dateigröße.
- **Header:** Magic, `format_version`, Modus, KDF-Parameter und Salt bzw. KEM-Chiffrat, eingepackter Dateischlüssel, Nonce-Präfix, Blockgröße. Der gesamte Header ist als AAD an jeden Block gebunden. Strenge Grenzen beim Lesen (Abschnitt 4 gilt sinngemäß, Downgrade-Schutz).
- **Inhaltsprüfsumme:** SHA3-256 des Klartexts (bei Ordnern pro Datei) wird **innerhalb** des verschlüsselten Teils mitgeführt und nach dem Entschlüsseln geprüft (Ende-zu-Ende-Kontrolle gegen Lese-/Schreibfehler). Sie wird nie im Klartext gespeichert, da sie Rückschlüsse auf den Inhalt erlauben würde.
- **Ordner:** Ein Ordner wird zu **einem** verschlüsselten Archiv (eigenes minimales Format: Typ, relativer Pfad, Größe, Inhalt, Prüfsumme). Dateinamen, Anzahl und Struktur bleiben verborgen. Kein Einsatz der Crate `tar` (Historie von Entpack-Schwachstellen).
- **Entschlüsseln:** Ausgabe zunächst in temporäre Dateien, Freigabe (Umbenennen) erst nach vollständiger Authentifizierung und Prüfsummenkontrolle; bei Fehlern keine Teilausgabe. Vorhandene Ziele werden nie überschrieben.
- **Pfadsicherheit beim Entpacken:** Ablehnung von `..`, absoluten Pfaden, Laufwerksbuchstaben/UNC, Steuerzeichen, Windows-reservierten Namen und zu langen Pfaden; Grenzen für Einträge und Verschachtelungstiefe. Symlinks, Geräte und Pipes werden beim Verschlüsseln nicht verfolgt (übersprungen und gemeldet) und beim Entpacken nie angelegt. Im Empfänger-Modus kann jeder mit dem öffentlichen Schlüssel gültige Dateien erzeugen; der Parser muss daher auch bösartige, korrekt verschlüsselte Archive sicher abweisen.
- **Nicht übernommen (Standard):** Zeitstempel, Eigentümer, Rechte (nur Inhalt und Struktur); Zeitstempel und erweiterte Attribute künftig optional verschlüsselt (U5), Eigentümer und setuid/setgid nie. Entschlüsselte Dateien erhalten restriktive Rechte (Linux `0600`/Ordner `0700`).
- **Originale:** werden nicht gelöscht; sicheres Löschen ist auf SSDs unzuverlässig (Abschnitt 5b).
- **Geplante Erweiterungen (spätere Updates):** Spiegel-Modus (Ordnerstruktur erhalten, jede Datei einzeln verschlüsselt), mehrere Empfänger pro Datei, optionale ML-DSA-Signatur des Absenders.
- **Dokumentation:** `docs/FILE_FORMAT.md` (DE/EN), Ergänzung in `docs/THREAT_MODEL.md` (sichtbare Metadaten: ungefähre Größe; Angriffe über manipulierte Archive).

## 4b. Passphrase-Wechsel privater Schlüsseldateien (#109)

- Opt-in `rekey FILE --out PATH`; verdeckte alte/neue Eingabe mit Bestätigung oder drei begrenzte
  Stdin-Zeilen. Bestehende Befehle unverändert; neuer Befehl lehnt mehrdeutiges `--passphrase-file` ab.
- Material, ID, öffentlicher Schlüssel, Zeit, Metadaten, Format und Faktor erhalten; frische Salt/Nonce.
  KDF standardmäßig exakt gleich, ausdrückliche Core-Anpassung ohne Senken von m/t/p. Keine Migration.
- Bestehende fremde Ziele/Sicherungen nie ersetzen; Austausch nur bestätigt mit `--force` und zuerst
  neuer exakter verschlüsselter `--backup`. Strikte Veröffentlichung ohne Ersetzen benötigt Hardlinks.
- Vertrauenswürdige Verzeichnisse/ein Schreiber; kein atomarer CAS, automatischer Restore, sicheres
  Löschen oder Widerruf alter Kopien. Eltern-sync best effort, keine OS-/Stromverlustgarantie.
  [REKEY.md](REKEY.md) und [security/REKEY_DESIGN.md](security/REKEY_DESIGN.md) nennen Plattformgrenzen
  und Testinvarianten.


## 4c. Authentisierte Archivliste (#117)

- Opt-in `list DATEI.pqkf`, eine Quelle, dieselben Passphrase-/Schlüssel-/Faktor-Zugänge wie decrypt.
- Gemeinsamer privater Scan für check/list; vorhandene v1/v2-Parser und Pfadregeln, keine Extraktion.
- Alle Inhaltsprüfsummen, Pfade/Konflikte, Archiv- und STREAM-Ende vor Rückgabe/Ausgabe prüfen.
- List-only maximal 10.000 Einträge und 16 MiB UTF-8-Pfadbytes; kein Temp-Spool/Abschneiden/Fallback.
  Inhalt gestreamt, Metadaten/Prüfstrukturen zusätzlich begrenzt; keine konstante Gesamt-RAM-Zusage.
- Nur list zeigt bewusst vertrauliche Archivpfade: JSON `pqkeep-list/1`; bestehendes
  `pqkeep-json/1` unverändert. Frühe Fehler im List-Schema, Ausgabefehler mit echtem Fehler-Exit.
- Integrität ist keine Absenderidentität; keine GUI, IPC-/Fortschritts-/Resume-API oder Formatänderung.
  [Anleitung](LIST.md), [Abgrenzung und Testfälle](security/LIST_DESIGN.md); allgemeine API bleibt #98.

## 5. Automatisierung & CI/CD (GitHub Actions)

- Trigger: jeder Push und Pull Request, Matrix `ubuntu-latest` und `windows-latest`, Rust stable (+ MSRV-Job).
- Pflicht-Jobs: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --locked`, Zeilenlimit-Check (max. 300), `cargo audit` oder `cargo deny` (Advisories, Lizenzen, verbotene Crates).
- Workflow-Härtung: `permissions: contents: read`, Actions auf Commit-SHA pinnen, Dependabot für Cargo und Actions, kein `pull_request_target`.
- **Keine Secrets** im Repository oder in Workflows. Tests erzeugen alle Passphrasen und Schlüssel zur Laufzeit dynamisch (Generator, temporäre Verzeichnisse via `tempfile`). Negativtests dürfen bewusst schwache Beispielwerte als Testdaten nutzen, aber nie echte oder wiederverwendete Geheimnisse.
- Zusätzliche Prüfungen: Secret-Scanning mit Push Protection (GitHub) und `gitleaks` im CI; Test-Check „keine `#[test]` in `src/` außer `*_tests.rs`“.
- Release und Signierung: siehe Abschnitt 5a.
- Vorschau-Builds (wöchentlich, `preview.yml`, #269): derselbe Build wie bei Releases (`build.yml`), als Sigstore-signiertes GitHub-Pre-Release mit Build-/SBOM-Attestationen (nie „Latest“, die letzten vier bleiben); im Programm gekennzeichnet (`+preview.` in `--version`, Banner, Fenstertitel). Betas und Releases bleiben unverändert; Details in `docs/RELEASE.md`.

## 5a. Release-Signierung & Lieferkette (Pflicht für Releases **und** Betas)

Alle veröffentlichten Artefakte (Release, Beta, Release Candidate) müssen signiert und nachprüfbar sein. Betas durchlaufen **denselben** Prozess, nur mit Tag `vX.Y.Z-beta.N` und als „Pre-release“ markiert.

- **Auslöser:** Nur ein **signierter Git-Tag** (`v*`) startet den Release-Workflow. Tags werden lokal signiert (SSH- oder GPG-Signatur). Der Workflow bricht ab, wenn die Tag-Signatur nicht verifizierbar ist.
- **Schutz des Hauptzweigs:** Ruleset auf `main`: nur per Pull Request, erforderliche Status-Checks, **signierte Commits erforderlich**, lineare Historie, keine Force-Pushes, kein Löschen, `CODEOWNERS`. Solange es nur einen Maintainer gibt, **0 Pflicht-Reviews** (sonst blockiert er sich selbst); Beiträge Dritter werden vor dem Merge geprüft.
- **Build-Provenienz:** `actions/attest-build-provenance` (GitHub Artifact Attestations, SLSA-Provenance) für jedes Artefakt, Linux und Windows.
- **Keyless-Signatur:** Zusätzlich `cosign sign-blob` (Sigstore, OIDC-Identität des Workflows). Dafür sind **keine** hinterlegten privaten Schlüssel nötig, passend zur Regel „keine Secrets im Repo“.
- **Prüfsummen:** `SHA256SUMS` für alle Artefakte, selbst signiert und als Release-Asset beigefügt.
- **SBOM:** CycloneDX- oder SPDX-SBOM (z. B. `cargo-cyclonedx`) erzeugen, an das Release hängen und attestieren.
- **Windows-Binary:** Zusätzlich Authenticode-Signatur gegen SmartScreen-Warnungen über die **SignPath Foundation** (kostenlos für Open Source). Azure Artifact Signing (kostenpflichtig) ist nur die Ausweichlösung. Zugangsdaten (SignPath-API-Token) ausschließlich als GitHub-Environment-Secret, niemals im Repo.
  - **Voraussetzungen (müssen dauerhaft erfüllt bleiben):** öffentliches Repository, OSI-anerkannte Lizenz (Abschnitt 5c), **kein proprietärer Code** im Projekt, Multi-Faktor-Authentifizierung für alle Teammitglieder bei GitHub und SignPath, nur eigene Binaries signieren, Build ausschließlich über GitHub Actions aus dem öffentlichen Repository (Origin Verification).
  - **Pflichthinweis** (nach Zusage) in README und Release-Notes, offizieller Wortlaut: „Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)“ sowie die Seite „Code signing policy“ mit Teamrollen und Datenschutzsatz (`CODE_SIGNING_POLICY.md`).
  - **Bis zur Freigabe:** Im Workflow ist die Stelle für die Signatur (vor dem Verpacken) vorgesehen; die SignPath-Action wird erst nach der Zusage eingebaut, weil dafür die Projektdaten von SignPath nötig sind. Ohne ihn werden Windows-Artefakte unsigniert veröffentlicht, aber weiterhin per Attestation, Sigstore und Prüfsumme abgesichert. Die README weist dann auf die SmartScreen-Warnung hin.
- **Härtung des Release-Jobs:** Eigener Job mit GitHub Environment `release` (erforderlicher Reviewer), Berechtigungen nur dort: `contents: write`, `id-token: write`, `attestations: write`. Alle anderen Jobs: `contents: read`. Actions auf Commit-SHA gepinnt.
- **Reproduzierbarkeit:** `cargo build --release --locked`, `--remap-path-prefix`, festes `SOURCE_DATE_EPOCH`; Archive mit fester Reihenfolge und festen Zeitstempeln. Ziel: identischer Hash bei Wiederholung (soweit möglich, Abweichungen dokumentieren). Linux-Build auf Ubuntu 22.04 (glibc 2.35) für breite Kompatibilität.
- **Veröffentlichung:** Bauen → Signieren/Bereitstellen → vollständige Verifikation → separat freigegebener Release-**Entwurf** (#186). Vor dem Entwurf erneut gegen erwartetes Repository, Workflow, Ref und Commit prüfen; nur der Entwurfjob erhält Release-Schreibrechte. Veröffentlichung bleibt manuell (Ablauf: `docs/RELEASE.md`).
- **Verifikationsanleitung** (zweisprachig in der README): `gh attestation verify <datei> --repo <owner>/<repo>`, `cosign verify-blob ...`, `sha256sum -c SHA256SUMS`, Prüfung der Authenticode-Signatur unter Windows.
- **Tests:** Trockenlauf des Release-Workflows mit Beta-Tag; ein Verifikations-Job lädt die erzeugten Artefakte und prüft Attestation, Signatur und Prüfsumme automatisch.

## 5c. Lizenz & Open-Source-Reinheit

- **Lizenz (festgelegt):** **Apache License 2.0** (OSI-anerkannt, enthält eine Patentklausel, passend für Kryptografie). Datei `LICENSE` (Volltext) und `NOTICE` im Repo-Root, `license = "Apache-2.0"` in `Cargo.toml`. Alle Abhängigkeiten müssen mit Apache-2.0 kompatibel sein (Allowlist in `deny.toml`, z. B. Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unicode-3.0; GPL/AGPL-Abhängigkeiten sind ausgeschlossen).
- **Ausnahme (freigegeben 07.11.2026):** Die EFF-Wortlisten (Daten, keine Software) stehen unter **CC BY 4.0** (keine OSI-Lizenz). Sie werden als Datendateien unter `data/wordlists/` mit Namensnennung in `NOTICE` mitgeliefert. Alle übrigen Wortlisten stehen unter OSI-Lizenzen (MIT, BSD-3-Clause). Listen mit „nicht kommerziell“-Klauseln (z. B. CC BY-NC) bleiben ausgeschlossen.
- **Kein proprietärer Code:** Weder im eigenen Code noch in Abhängigkeiten, Vendor-Verzeichnissen, Binärblobs oder eingebetteten Ressourcen. Keine vorkompilierten Binärdateien im Repo. **Ausnahme (v2.13):** eigene Bilder der Dokumentation unter `docs/images/` (PNG, JPEG, WebP, höchstens 500 KB je Datei), lizenziert wie das Projekt.
- **Automatische Prüfung:** `cargo deny` mit Lizenz-Allowlist (nur OSI-anerkannte, kompatible Lizenzen), Verbot unbekannter Registries/Git-Quellen und Prüfung auf Crates ohne Lizenzangabe. Zusätzlich Check, dass keine Binärdateien eingecheckt sind (außer den Bildern unter `docs/images/`, deren Endung, Größe und Dateisignatur geprüft werden).
- **Beiträge:** `CONTRIBUTING.md` (DE/EN) mit Hinweis, dass eingereichter Code unter derselben Lizenz steht und keinen proprietären Code enthalten darf.
- **Dokumentation:** Lizenz und Hinweis zur Code-Signierung in der zweisprachigen README.

## 5b. Weitere Sicherheitsmaßnahmen

- **Passphrase-Normalisierung:** Unicode **NFKC** vor der Ableitung, sonst kann dieselbe Passphrase unter Windows und Linux zu unterschiedlichen Schlüsseln führen.
- **Optionaler zweiter Faktor:** Keyfile oder „Pepper“ (separate Datei) zusätzlich zur Passphrase in die Ableitung einbeziehen.
  - DE: Faktordatei (32 Zufallsbytes) als Argon2id-Secret, siehe [V2_DRAFT.md](V2_DRAFT.md); im Core, auf der Kommandozeile (`pqkeep factor`, `--factor-file`) sowie in Menü, geführtem Ablauf und Kontextmenü umgesetzt, v1 unverändert.
  - EN: Factor file (32 random bytes) as Argon2id secret, see [V2_DRAFT.md](V2_DRAFT.md); implemented in the core, on the command line (`pqkeep factor`, `--factor-file`) and in menu, guided flow and context menu, v1 unchanged.
- **Downgrade-Schutz:** Container mit zu alter `format_version` oder zu schwachen KDF-Parametern werden abgelehnt oder nur mit expliziter Warnung/Bestätigung geöffnet.
- **Dateirechte beim Laden prüfen:** Unter Linux Warnung bei `group/world`-lesbaren Containern. Unter Windows Ablage im Benutzerprofil mit eingeschränkter ACL.
- **Kein Clipboard, keine Historie:** Passphrasen werden nie automatisch in die Zwischenablage kopiert, nie als Argument übergeben (Shell-History) und im Terminal nicht angezeigt (Ausnahme: Generator, nur auf ausdrücklichen Wunsch).
- **Core Dumps und Swap:** Core Dumps für den Prozess deaktivieren und Speicherseiten mit Geheimnissen sperren (`mlock`/`VirtualLock`), in isolierten, kommentierten Modulen. Speichersperren sind zwingend (kein Fallback); Prozess-/OS-/Compilergrenzen bleiben ehrlich dokumentiert.
- **Compiler-/Linker-Härtung:** `overflow-checks = true` auch im Release, `lto`, `codegen-units = 1`, `strip`, `panic = "abort"` (nur Release; Destruktoren laufen bei Panik nicht – vertretbar, da Core Dumps gesperrt sind). Linux: PIE, Full RELRO (`-z relro -z now`), NX-Stack. Windows: ASLR (High Entropy), DEP, Control Flow Guard. Ein CI-Job prüft diese Merkmale am gebauten Release-Binary (`scripts/check_binary.py`).
- **Lieferkette:** `cargo deny` mit Allowlist für Lizenzen und Quellen, zusätzlich wöchentlicher geplanter Advisory-Lauf (`.github/workflows/audit.yml`), möglichst wenige Abhängigkeiten, optional `cargo vet`, OpenSSF-Scorecard-Workflow, Dependabot, 2FA für alle Maintainer.
- **Fuzzing:** `cargo-fuzz` für Container-Parser und API-Eingaben, regelmäßig per geplantem Workflow.
- **API zusätzlich:** Optionales TLS (rustls) mit modernen Cipher Suites, Token nur als Hash gespeichert, Sperre nach wiederholten Fehlversuchen, Sicherheits-Header, kein CORS standardmäßig.
- **Backup und Rotation:** Doku zu Sicherung der Container, Schlüssel-Rotation und Ablaufdatum. Hinweis: Sicheres Löschen auf SSDs ist unzuverlässig, daher Verschlüsselung statt Löschen als Schutzprinzip.
- **Optional prüfen:** Hybrid-Verfahren (z. B. X25519 + ML-KEM) für Übergangszeit, mit eigener Entscheidung dokumentiert.

## 6. Verzeichnisstruktur (Vorschlag)

```
pqkeep/
├─ Cargo.toml / Cargo.lock / deny.toml / rust-toolchain.toml
├─ src/  lib.rs  main.rs  error.rs  security.rs  envelope.rs  cli.rs  api.rs
│        crypto/ (mod.rs, kem.rs, dsa.rs, kdf.rs, aead.rs, stream.rs, wrap.rs)
│        files/  (mod.rs, format.rs, archive.rs, paths.rs)
├─ tests/  integration_*.rs   (+ tests/kat/ für Known-Answer-Tests, tests/cli_help.rs)
│        (interne Tests: src/**/<modul>_tests.rs, nur per #[cfg(test)] mod eingebunden)
├─ scripts/  check_limits.sh  (Zeilenlimits, keine #[test] in Produktionsdateien)
├─ docs/  THREAT_MODEL.md  FORMAT.md  FILE_FORMAT.md  CRYPTO.md
├─ README.md (DE/EN)  SECURITY.md  CONTRIBUTING.md  CODE_SIGNING_POLICY.md
├─ LICENSE (Apache-2.0)  NOTICE  CLAUDE.md  docs/ROADMAP.md  docs/CHECKLIST.md
└─ .github/workflows/ci.yml  dependabot.yml
```

## 7. Fahrplan (Step-by-Step)

Jeder Schritt wird erst nach grünem `cargo test` und Freigabe abgeschlossen. Pro Datei max. 300 Zeilen.

### Schritt 0: Projekt-Grundgerüst
- Aufgabe: Cargo-Projekt, Lints (`forbid(unsafe_code)`, Clippy-Konfiguration), `error.rs` (`thiserror`, keine Geheimnisse in Fehlertexten), CI-Rumpf mit Zeilenlimit-Check.
- Test: leerer Build und Lint auf beiden Plattformen.

### Schritt 1: Core-Krypto (`crypto/`)
- Aufgabe: ML-KEM- und ML-DSA-Schlüsselerzeugung, AES-256-Schlüsselerzeugung, Argon2id-Ableitung, AES-256-GCM-Verschlüsselung/Entschlüsselung des privaten Schlüssels.
- Tests:
  - Roundtrip: Erzeugen, Verschlüsseln, Entschlüsseln mit korrekter Passphrase; KEM-Encaps/Decaps und Sign/Verify funktionieren mit dem wiederhergestellten Schlüssel.
  - Fehlschlag bei falscher Passphrase, bei jedem einzelnen manipulierten Byte (Ciphertext, Tag, Nonce, Salt, AAD/Metadaten) und bei abgeschnittenen Daten.
  - Known-Answer-Tests (NIST-Testvektoren) für ML-KEM/ML-DSA, soweit die Crate sie zulässt.
  - KDF-Grenzwerte: zu schwache und zu hohe Parameter werden abgelehnt.
  - Zeroize: Typ-Level-Test, dass alle Geheimnistypen `ZeroizeOnDrop`/`Zeroizing` sind, plus Test, dass `zeroize()` den Puffer tatsächlich nullt. Ehrliche Doku zu den Grenzen.
  - Nonce-Eindeutigkeit über viele Verschlüsselungen.

### Schritt 2: Validierung & Passphrase (`security.rs`)
- Aufgabe: Stärkeprüfung (Abschnitt 3.3), Entropieschätzung, Generator.
- Tests: schwache Passphrasen werden mit nachvollziehbarem Grund abgelehnt (zu kurz, fehlende Klassen, Muster, Blocklist); starke werden akzeptiert; Generator liefert in N Durchläufen stets gültige, voneinander verschiedene Werte mit erwarteter Länge und Klassenabdeckung; Entropiewert stimmt mit Formel überein; Unicode-Grenzfälle.

### Schritt 2a: Speicher- und Prozesshärtung (`hardening/`)
- Aufgabe: Speicherseiten mit Geheimnissen sperren (mlock/VirtualLock, Seitenzähler), Core-Dump-Sperre und „nicht dumpbar“ (Linux), sofortiges Nullen nach Nutzung; ohne eigenen `unsafe`-Code. Details: `docs/MEMORY_HARDENING.md`.
- Tests: Sperren/Freigeben, gemeinsame Seiten, Weiterlaufen bei verbotenem Sperren, Core-Dump-Grenze.

### Schritt 2b: Wortlisten und Wort-Modell (`security/dictionary.rs`)
- Aufgabe: Entropieschätzung nach dem Wort-Modell (Buchstabenfolgen höchstens wie Wörter, Listenwörter ≈ 12,9 Bit, Ziffern log2(10), wiederholte Trennzeichen 1 Bit) mit eingebundenen Wortlisten (EFF, BIP-39, deutsche Diceware-Listen); Grund „besteht überwiegend aus Wörtern“.
- Tests: zusammengesetzte Wörter werden abgelehnt (z. B. „FIPS-140-validiert“), lange Sätze und Zufallszeichen angenommen, Formelwerte nachgerechnet.

### Schritt 3: Container (`envelope.rs`)
- Aufgabe: Struktur (Abschnitt 4), Serialisierung, Deserialisierung, Validierung der Metadaten.
- Tests: Roundtrip; Ablehnung unbekannter Felder, falscher Version, übergroßer oder fehlerhaft kodierter Daten; Pfadkonventionen Windows (`C:\Users\...`, Backslashes) und Linux (`/home/...`) via `PathBuf` und `tempfile`; atomares Schreiben; Dateirechte unter Linux; Fuzz-Test oder Property-Test (`proptest`) für den Parser (keine Panics).

### Schritt 3a: Datei- und Ordnerverschlüsselung (`files/`, `crypto/stream.rs`, `crypto/wrap.rs`)
- Aufgabe: Abschnitt 4a umsetzen: Streaming-AEAD, Einpacken des Dateischlüssels (Passphrase, ML-KEM-Empfänger), Header, Archivformat für Ordner, Pfadprüfung, atomare Ausgabe, Inhaltsprüfsumme.
- Tests: Roundtrip leerer, kleiner, blockgenauer und großer Dateien (mehrere Blöcke); Ordner mit Unterordnern, leeren Ordnern und Unicode-Namen; Manipulation jedes Header-Bytes und von Blöcken (kippen, vertauschen, abschneiden, anhängen); falsche Passphrase bzw. falscher Schlüssel; bösartige Archive (Pfad-Traversal, absolute und Windows-Pfade, Symlink-Einträge, zu viele Einträge, falsche Prüfsumme); keine Teilausgabe bei Fehlern; vorhandenes Ziel wird nicht überschrieben; Property-Tests für Header- und Archiv-Parser (keine Panics).

### Schritt 4: CLI (`cli.rs`, `clap` + `dialoguer`)
- Aufgabe: Interaktives Menü **und** nicht-interaktive Subcommands (`generate`, `validate`, `inspect`, `export`, `passphrase`, `encrypt`, `decrypt`, `help`). Verdeckte Passphrase-Eingabe, Bestätigung vor Überschreiben, Ausgabe nur in vom Nutzer gewählte Pfade (Pfad-Validierung).
- **Minimale Rechte:** Die CLI benötigt keine Administrator-/root-Rechte und gibt eine deutliche Warnung aus, wenn sie mit solchen Rechten gestartet wird. Erster Aufruf beim Start: `hardening::harden_process()`.
- **Integrierte Hilfe (zweisprachig DE/EN, per `--lang de|en`, Standard aus System-Locale):**
  - `--help` und `-h` global und pro Subcommand, jeweils mit Beschreibung, Parametern, Beispielen und Exit-Codes.
  - `pqkeep help <thema>` mit Themen: `passphrase` (Regeln und Generator), `files` (Datei-/Ordnerverschlüsselung, Modi, Grenzen), `algorithms` (ML-KEM/ML-DSA/AES, Parametersätze), `container` (Format und Metadaten), `security` (Sicherheitshinweise und Grenzen), `verify` (Release-Signaturen prüfen).
  - Im interaktiven Menü ein Eintrag „Hilfe / Help“ sowie kontextbezogene Kurzhinweise bei jeder Eingabe (z. B. Passphrase-Regeln, Hinweis auf Metadaten im Klartext).
  - Manpage (`clap_mangen`) und Shell-Completions (`clap_complete`, bash/zsh/fish/PowerShell) werden per Subcommand `pqkeep completions <shell>` bzw. `pqkeep man` erzeugt, ohne Netzwerkzugriff.
- Tests (in eigenen Dateien): simulierte Eingaben (Integrationstests mit `assert_cmd`), erfolgreicher Export des Containers, erneutes Einlesen und Entschlüsseln, saubere Fehlermeldungen bei ungültigen Eingaben, Exit-Codes. Hilfetests: Jeder Subcommand und jedes Hilfethema liefert Text in **beiden** Sprachen, `--help` enthält mindestens ein Beispiel, kein Hilfetext enthält Beispielgeheimnisse, die wie echte Zugangsdaten aussehen.

### Schritt 5: API (`api.rs`, Axum)
- Aufgabe: Endpunkte `POST /v1/generate`, `POST /v1/validate`, `GET /v1/health`. Strikte JSON-Schemata. Datei-/Ordnerverschlüsselung (Abschnitt 4a) ist bewusst **nicht** über die API verfügbar.
- Härtung: Standard-Bind **127.0.0.1**, Anbindung an andere Interfaces nur explizit und mit Warnhinweis (TLS-Terminierung durch Reverse Proxy dokumentieren); Authentifizierung per Token aus Datei/Umgebung (konstante Zeit); Body-Größenlimit, Timeouts, Rate-Limiting; Argon2-Arbeit in `spawn_blocking` mit Semaphore (Begrenzung paralleler KDF-Jobs gegen DoS); keine Geheimnisse in Logs; generische Fehlerantworten ohne interne Details. `/v1/validate` füllt jede Antwort auf eine feste Mindestdauer auf, damit die Antwortzeit keine Rückschlüsse auf den Aufbau der Passphrase erlaubt (die Prüfung selbst ist nicht zeitkonstant). Token-Vergleich in konstanter Zeit (`subtle`).
- Tests: HTTP-Integrationstests für alle Endpunkte (Erfolg, ungültige Eingabe, fehlende Auth, zu große Bodies, manipulierte Container, Parallelitätslimit).

### Schritt 5a: Sandboxing (Linux)
- Aufgabe: Nach dem Start Rechte einschränken. **Landlock**: Dateizugriff nur auf die vom Nutzer gewählten Pfade (CLI) bzw. konfigurierte Pfade (API). **Seccomp-BPF**: nur benötigte Systemaufrufe; in der CLI kein Netzwerk, kein `execve`, kein `ptrace`; die API zusätzlich nur `accept` auf dem eigenen Socket. Profile getrennt für CLI und API, abgeleitet aus den tatsächlich genutzten Systemaufrufen (inkl. Argon2-Threads). Ältere Kernel ohne Landlock: Warnung statt Abbruch. Windows: kein gleichwertiges Verfahren ohne großen Aufwand (AppContainer) – dokumentiert.
- Tests: verbotene Zugriffe (Datei außerhalb der Freigabe, Netzwerk in der CLI, `execve`) schlagen fehl; normale Abläufe (generate, encrypt/decrypt, API-Anfragen) funktionieren unverändert.

### Schritt 6: CI/CD & Dokumentation
- Aufgabe: vollständige `ci.yml` (Abschnitt 5), `release.yml` mit Signierung (Abschnitt 5a), `SECURITY.md` (Meldeweg), `THREAT_MODEL.md`, `FORMAT.md`, zweisprachige `README.md` (Installation, Nutzung, Sicherheitshinweise, Grenzen, Verifikation von Releases).
- Tests: Workflow läuft grün auf Linux und Windows; Beta-Trockenlauf des Release-Workflows inklusive automatischer Verifikation von Attestation, Signatur und Prüfsumme; Dokumentationsbeispiele werden als Doctests oder Smoke-Tests ausgeführt.

### Schritt 7: Abschluss-Review
- Aufgabe: Sicherheits-Selbstreview (Checkliste: Geheimnisse in Logs/Fehlern, `unwrap`/`expect` in Produktionspfaden, Panics, Parameterlimits, Abhängigkeitsbaum, Maßnahmen aus 5b umgesetzt), `cargo audit`/`deny` ohne offene Funde, erste signierte Beta (`v0.1.0-beta.1`) veröffentlichen und die Verifikation nach Anleitung selbst nachvollziehen.

## 9. Geplante Updates (nach `v0.1.0-beta.1`)

Jedes Update ist ein eigener Schritt mit Plan, Freigabe, Tests und Definition of Done. Reihenfolge nach Abhängigkeiten.

### U1: Digitale Signaturen (ML-DSA-87)
- Datei signieren mit dem eigenen privaten ML-DSA-Schlüssel; abgesetzte Signaturdatei (`<datei>.pqsig`) mit Format-Version, Algorithmus, Schlüssel-ID des Signierers, SHA3-512 der Datei, Zeitstempel, Kontext-String und Signatur. Große Dateien werden gestreamt gehasht (kein Laden in den Speicher). Format: `docs/SIGNATURE_FORMAT.md` (v1, nur ML-DSA-87; Dateiname nicht signiert; Zeitstempel ist eine Angabe des Signierers).
- Prüfen mit dem öffentlichen Schlüssel: Ausgabe eindeutig `[VERIFIED]` oder `[INVALID]` (Exit-Code 0 bzw. ≠ 0); Anzeige der Schlüssel-ID/des Fingerabdrucks des Signierers.
- **Ehrliche Einordnung:** Die Signatur beweist, dass die Datei unverändert ist und vom Inhaber des privaten Schlüssels signiert wurde. Wer dieser Inhaber ist, muss über den Fingerabdruck auf einem zweiten Weg bestätigt werden. Sie ist **keine** qualifizierte elektronische Signatur nach eIDAS (dafür wären ein qualifiziertes Zertifikat und ein Vertrauensdiensteanbieter nötig); „rechtssicher“ im juristischen Sinn ist sie damit nicht.
- Erweiterung für `.pqkf`: optionale Absender-Signatur im Container (ersetzt den bisherigen Eintrag „optionale ML-DSA-Signatur des Absenders“).
  - DE: Umgesetzt (#44) als Format v3 ([V3_SIGNED.md](V3_SIGNED.md)): `pqkeep encrypt --sign-with <schlüssel>` (optional `--sign-factor-file`), `decrypt`/`check` prüfen immer und nennen den Absender, `--signer <pub>` verlangt einen bestimmten Absender (sonst Exit-Code 7, keine Ausgabe); `inspect` zeigt den Absender ungeprüft. Menü und Kontextmenü bieten die Signatur seit #287 an; die REST-API nicht (dort keine Dateiverschlüsselung).

### U2: Mehrere Empfänger (Multi-Recipient-Container)
- Ein zufälliger AES-256-GCM-Dateischlüssel (wie bisher); im Header pro Empfänger ein eigener Eintrag (ML-KEM-Kapselung, Standard ML-KEM-1024, Empfänger-ID, eingepackter Schlüssel). Jeder Empfänger öffnet mit seinem eigenen privaten Schlüssel; kein geteiltes Passwort.
- Grenzen: Höchstzahl Empfänger (z. B. 64), neue `format_version` mit Downgrade-Schutz, Tests für jeden Empfänger, falsche/fehlende Empfänger, manipulierte Einträge.
- Entscheidung im Plan: Empfänger-IDs sichtbar (schnelles Finden des eigenen Eintrags) oder verborgen (Probe-Entschlüsselung, mehr Privatsphäre). Entwurf zusammen mit U0: [V2_DRAFT.md](V2_DRAFT.md) (Vorschlag: sichtbar). Optional anonyme Empfänger als Ausnahme: U5 (#316).
  - DE: Umgesetzt im Core (#46) und auf der Kommandozeile (#47): `--to` mehrfach (bis 64, jede ML-KEM-Stufe), optional mit eigener Passphrase (`--with-passphrase`, auch mit Faktordatei); ein einzelner Empfänger bleibt v1. Menü und Kontextmenü fragen nach jedem bestätigten Empfänger „weiterer?“; die zusätzliche eigene Passphrase bietet nur das Menü an.
  - EN: Implemented in the core (#46) and on the command line (#47): repeated `--to` (up to 64, any ML-KEM level), optionally with an own passphrase (`--with-passphrase`, also with a factor file); a single recipient stays v1. Menu and context menu ask "another?" after each confirmed recipient; only the menu offers the additional own passphrase.

### U3: Einrichtungs-Assistent (Konsole)
- Beim ersten Start ein farbiger, interaktiver Konsolen-Assistent (Terminal-UI-Crates, Auswahl im Plan): 1. sichere Master-Passphrase (Regeln aus 3.3, Argon2id), 2. eigenes Schlüsselpaar ML-KEM-1024 (Verschlüsselung) und ML-DSA-87 (Signaturen), 3. optional Registrierung des Kontextmenüs (U4), 4. Einweisung und Notfall-Backup (Kopie der Schlüsseldateien an einen gewählten Ort, Hinweise zur sicheren Aufbewahrung, Prüf-Wiederherstellung).
- Ablage im Benutzerprofil (Linux `~/.local/share/pqkeep`, Windows `%APPDATA%\PQKeep`), Rechte wie Abschnitt 4. Erneut aufrufbar (`pqkeep setup`), überschreibt nie ohne Bestätigung.

### U4: Kontextmenü (Rechtsklick) mit Passphrase-Dialog
- Aktionen „Mit PQC sichern“ / „PQC entschlüsseln“ (später „Signieren“/„Prüfen“) im Dateimanager. Registrierung nur auf Benutzerebene, ohne Administratorrechte, vollständig rückgängig zu machen: Windows `HKCU\Software\Classes\…\shell`; Linux Nemo-Actions (Cinnamon/Mint), Nautilus-Skripte, Dolphin-Service-Menüs, Thunar-Aktionen (`uca.xml`, Xfce).
- Ohne Terminal öffnet sich ein schlankes Eingabefenster für die Passphrase. **Abweichung von Abschnitt 1 („GUI ist Non-Goal“):** nur dieser Dialog, keine Anwendungsoberfläche; Umsetzung im Plan zu entscheiden (z. B. vorhandene Systemwerkzeuge wie `zenity`/`kdialog` unter Linux bzw. ein minimaler nativer Dialog unter Windows). Übergabe der Passphrase nur über Pipe/Speicher, nie über Argumente oder Umgebungsvariablen.

### U5: Privatsphäre und Metadaten (optional, konfigurierbar)
Alle Funktionen sind **optional und standardmäßig aus**; ohne Option bleiben Formate und Ausgaben unverändert (Grundsatz D3: neues Format nur, wenn eine Option es verlangt; ältere Versionen melden „nicht unterstützt“, nie still). Konfiguration: Einzeloptionen pro Aufruf, Stufe `--privacy high` setzt die Privatsphäre-Optionen gemeinsam, Menü und Kontextmenü bieten nur diese Stufe, dauerhafte Voreinstellungen über Profil/Einrichtung (#136, #48–#50) – keine eigene Konfigurationsdatei.
- **Zufällige äußere Dateinamen** (`--random-name`, #315): keine Rückschlüsse auf den Inhalt aus dem `.pqkf`-Namen; der Originalname steht verschlüsselt im Archiv und wird beim Entschlüsseln wiederhergestellt. Kein Formatwechsel. **Umgesetzt** (CLI `--random-name`/`--privacy high`, `decrypt --original-name` bzw. automatisch, Menü; Kontextmenü entschlüsselt; Details [FILE_FORMAT.md](FILE_FORMAT.md)).
- **Formatentwurf v4** für Padding, anonyme Empfänger, verborgenen Absender und Strom-Modus (#83): [V4_DRAFT.md](V4_DRAFT.md) (Entscheidungen P1–P9). Schritt 1 (Kern: Optionsbits, Schlüsselbindung, Abschluss-Block, Inhalt „Strom“), Schritt 2 (`encrypt --stdin`, #83) und Schritt 3 (Füllung `--pad`) umgesetzt.
- **Padding** (`--pad`, #316): verbirgt die genaue Dateigröße durch authentisierte Füllbytes (PADMÉ, höchstens ~12 % Mehrgröße).
- **Anonyme Empfänger** (`--anonymous-recipients`, #316): Zugänge ohne Empfänger-ID, Öffnen per Probe-Entkapselung; **optionale Ausnahme von D1** (sichtbare IDs bleiben Standard).
- **Verborgener Absender** (`--hide-sender`, #316): Absenderschlüssel und Signatur (U1, Format v3) im verschlüsselten Teil; prüfbar nur für Empfänger, Schlüsselbindung bleibt.
- **Verschlüsselte Zeitstempel** (`--keep-times`, #123): Änderungszeit verschlüsselt im Archiv-Eintrag, beim Entschlüsseln gesetzt (Abweichung von Abschnitt 4a nur mit dieser Option).
- **Verschlüsselte erweiterte Attribute** (`--keep-xattr`, #123): standardmäßig nur `user.*`; `security.*` (z. B. Programmrechte), `trusted.*`, `system.*`/ACLs und SELinux-Kennungen nie automatisch wiederherstellen; Eigentümer und setuid/setgid nie; Größen- und Anzahlgrenzen; Windows eigener Schritt.
- **Reihenfolge:** #315 → Formatentwurf #316 gemeinsam mit #83 und **vor #98** → Archiv-Erweiterung (Zeitstempel/Attribute) im Backup-Epic (#123, #113); Konzept abgestimmt mit dem Vault-Index (#263). Jeder Schritt mit eigenem Plan, Formatentwurf, Tests und Angriffskatalog-Fällen.

### Weitere Updates
- Spiegel-Modus für Ordner (Struktur erhalten, Dateien einzeln verschlüsselt).
- Diceware-Generator mit eigener bzw. gemeinfreier Wortliste (DE/EN), keine CC-BY-Liste (Abschnitt 5c).

## 8. Definition of Done (pro Schritt)

- [ ] Produktionsdateien ≤ 300 Zeilen, Funktionen ≤ 50, Testdateien ≤ 400; Tests ausschließlich in eigenen Dateien
- [ ] Kommentare/Doku/Hilfetexte zweisprachig (DE/EN)
- [ ] `fmt`, `clippy -D warnings`, `cargo test --locked` grün auf Linux **und** Windows
- [ ] Keine hartcodierten Geheimnisse, keine `unwrap()`/`expect()` in Produktionscode
- [ ] Negativ- und Grenzwerttests vorhanden, nicht nur der Erfolgsfall
- [ ] Kurze Zusammenfassung: was gebaut, was getestet, bekannte Einschränkungen


Laufzeitnacharbeit #147: Zusätzliche Klartext-Dateipuffer entfernt; Signatur-Eingabe,
In-place-AEAD, Rekey-Framing und erzeugte API-Tokens verwenden gesperrten Speicher.
HTTP/1-Eingang mit gesperrten Hyper-Ownern und gesperrtem serde_json-Scratch umgesetzt;
externe Router-Caller verantworten ihre vorgelagerten Allokationen. Entschlüsselte
Archivnamen und Konfliktschlüssel liegen in ConfidentialText; ListEntry.path erfordert
explizites expose(), keine automatische Klartext-Serialisierung/Clone/Debug-Ausgabe.
Listing.entries verwendet ConfidentialEntries: vor dem ersten Datensatz vollständig
gesperrte feste Kapazität, keine Reallokation privater Typ-/Größen-/Owner-Datensätze.
Caller-eigene Vec-Konvertierung ist fallibel und bleibt eine explizite äußere Grenze.
Listen-JSON bleibt pqkeep-list/1 und wird nach vollständiger Authentisierung direkt
aus geliehenen Pfaden ausgegeben. TokenHash::of/verify sind wegen zwingender Sperren
fallibel. Typisierte Seeds und private Hashzustände werden vor privater Befüllung gesperrt.
Provider-Konstruktoren und Prozess-/Helper-Unterstützung bleiben offen; siehe
[Plattformplan](security/PLATFORM_SUPPORT_PLAN.md). Keine vollständige Schließung behauptet.
Geprüfte Main-Merges sind freigegeben; Host-/Registry-/Rechteänderungen weiterhin separat.

R6-Teilbehebung: NFKC verwendet bestehende gepinnte Unicode-Primitiven mit gesperrten
Zeichen-/Sortierbereichen und Klassenzählern statt TinyVec/Standard-Sort-Scratch.
Passphrase-Bytes und Grenzen bleiben gleich; alle Unicode-Skalare und der vollständige
Unicode18-Konformitätskorpus dienen als Gegenprobe. Andere Providerzustände bleiben offen.

Der eigene Provider-Wrapper hält eine feste, vollständig gesperrte Allokation.
Beim Drop zuerst den Provider an Ort und Stelle zerstören, anschließend sämtliche
früheren Belegungs-/Paddingbytes löschen und erst dann entsperren/freigeben.
Kein Ersatzkonstruktor im Drop; interne Provider-Arbeitsbereiche bleiben offen.

Interne UTF-8-Zeichenpositionen, nicht überlappende Wörterbuchbereiche und
positionsgenaue Mustermasken der Passphrasenbewertung liegen vor erster Befüllung
in festen gesperrten Puffern. Vollständige Allokationen vor Unlock löschen;
Sperrfehler weitergeben, keine ungesperrte Ersatzbewertung. Wörterbuchauswahl,
Entropieformel und bewusst öffentliche grobe Bewertungsergebnisse bleiben gleich.
Siehe [ASSESSMENT_METADATA_PLAN.md](security/ASSESSMENT_METADATA_PLAN.md).

R7-Teilbaustein: harden_process ergänzt/verifiziert unter Windows prozesslokales
WER-NOHEAP. Der zusätzliche Berichtswert ist keine vollständige Dumpsperre;
complete/core_dumps_disabled/not_dumpable bleiben falsch. Host-Policy und externe
Passworthelfer bleiben getrennt und offen. Keine Registry-/ACL-/Systemänderung.

R8-Teilbehebung: Interne Archiv-Framingbytes/Zähler und temporäre Eintragsdatensätze
liegen vor privater Befüllung in festen SecretBuffer-Ownern. Keine entschlüsselten
Array-Rückgaben oder to_le_bytes-Scratcharrays im Archivpfad. Reader/Writer und
Eintragsvorbereitung propagieren Sperrfehler; Verbraucher leihen Name/Typ/Größe.
Archivformat und öffentliche List-/Prüf-/Extraktionsverträge bleiben erhalten.
Keine Aussage über sämtliche Compiler-/Registerkopien oder OS-Dateisystemmetadaten;
Provider-/Helper-Grenzen bleiben offen. Siehe [Plan](security/ARCHIVE_METADATA_PLAN.md).

R6-Featurekorrektur: Der Produktionsgraph aktiviert blake2/zeroize ausdrücklich,
auch ohne API; Argon2/zeroize leitet dieses Feature nicht weiter. Damit ist die
bestehende Drop-Löschung von Blake2s privatem h/t-Corezustand aktiviert. Paketmenge,
Versionen, Quellen, Checksummen und KDF-Verhalten bleiben erhalten. Dies ersetzt
keine vorab gesperrten Arbeitsbereiche; Konstruktor-/Kompressions-/Hashausgabe-/
Worker-Grenzen bleiben offen. Siehe [Plan](security/BLAKE2_DROP_FEATURE_PLAN.md).

R8-Ownerschritt: ConfidentialText sperrt auch seinen privaten SecretBytes-Descriptor
vor Befüllung mit bestehendem SecretState. Namebytes bleiben separat gesperrt;
äußere Baum-Handles enthalten feste öffentliche Ownergeometrie. Explizites Zeroize
erhält einen gültigen leeren Text; Drop zerstört den inneren Owner gesperrt und
löscht seine gesamte ehemalige Allokation vor Unlock. Listen bereiten öffentliche
leere Slots vor und setzen Name/Typ/Größe direkt im gesperrten Datensatz; Fehler
nehmen den Slot zurück. Budgets, Sortierung und Ausgabegrenzen bleiben erhalten.
Baumtopologie, weitere Pfad-Arbeitsbereiche sowie R6/R7 bleiben offen. Siehe
[Plan](security/METADATA_OWNER_PLAN.md).

R8-Basisowner: SecretBytes hält seinen variablen Bytepuffer-Descriptor im bestehenden
stabilen SecretState, gesperrt vor privater Befüllung. Auch leere Werte benötigen
diese Sperre. Fallible Reservierung und Payloadsperre erfolgen direkt im geschützten
Descriptor, erst danach wird kopiert; privates Wachstum wird verweigert. new(Vec)
bleibt eine explizite Caller-Ownership-Grenze ohne Payloadkopie. Sperrfehler löschen
übernommene Callerbytes; Drop zerstört den Puffer gesperrt und löscht die gesamte
ehemalige Descriptorallokation vor Unlock. Öffentliche APIs bleiben erhalten.
Siehe [Basisplan](security/BYTE_OWNER_PLAN.md).

R8-Typowner: Geprüfte char-/usize-/bool-/WordSpan-/ListEntry-/u16-Pufferdescriptoren
liegen über SecretWorkspace ebenfalls vor Reservierung im stabilen gesperrten
SecretState. Gesamte Payloadkapazität vor Defaults/private Befüllung sperren, kein
privates Wachstum. Konkrete geprüfte Buffer-Drop-Marker statt pauschalem generischem
Vertrag. Explizite Caller-Listenübernahme ohne Payloadkopie; bei Sperrfehlern löschen.
Öffentliche API-/Normalisierungs-/Listen-/Ausgabeverträge bleiben erhalten. Andere
skalare, Pfad-/Quell-/Ausgabe-/Baumdaten und Provider-/Helper-Grenzen bleiben offen.
Siehe [Typplan](security/TYPED_OWNER_PLAN.md).

R8-Sperrbuchhaltung: Ein fester Anfang-/Ende-Datensatz ersetzt die zusätzliche
Seitenadressliste je Sperrbereich. Nur der tatsächlich erworbene zusammenhängende
Präfix wird freigegeben; gemeinsame Seiten bleiben bis zum letzten Nutzer gesperrt.
Geometrie-/Rundungs-/Budget-/Referenzzählerüberlauf kann keine vollständige Sperre
melden. Eigene Record-Felder nach Freigabe zeroisieren. Gemeinsame Registry,
temporäre Stack-/Compilerkopien und übrige R6/R7/R8-Grenzen bleiben offen.
Siehe [Teilplan](security/LOCK_RANGE_PLAN.md).

R8-Pfadteile: Sieben interne Pfadprüfungen verwenden vollständig vorab validierte,
geliehene Iteratoren statt gewöhnlicher Referenzlisten. Gesamten Pfad vor Übergabe
an Dateierzeugung prüfen; Unicode-/Sigma-Faltung, Byte-/Tiefenlimits und Konfliktregeln
bleiben erhalten. Öffentliche validate()->Vec- und PathSet::insert(&[&str])-Verträge
bleiben erhalten; normalisierte Schlüssel weiterhin zwingend sperren. Öffentliche
Callerlisten, Quell-/Ausgabepfade, Baum-/Skalarmetadaten und Stack-/Compilerkopien
bleiben offen. Siehe [Pfadteilplan](security/PATH_COMPONENT_PLAN.md).

R6/R8-Caller-Seeds: Feste typisierte 32-/64-Byte-Seeds direkt aus vorab gesperrten
SecretBytes ausleihen, ohne private Arraykopie oder zusätzlichen typisierten Owner.
Exakte Längenprüfung vor Konstruktion; Descriptor und Payload vor privater Kopie
sperren. Die bisherigen Payloads waren bereits gesperrt; zusätzliche innere
Seed-Vec-Descriptoren entfallen. Geprüfte Array-Leihsicht an den Owner binden;
falsche Größe verweigern. Frühes explizites Löschen und vollständiger Wipe vor
Unlock bleiben erhalten. Provideraufrufe und öffentliche Bytes unverändert. Providerinterne Seeds,
expandierte Zustände, Konstruktion/Scratch und übrige R6/R7/R8-Grenzen bleiben offen.
Siehe [Seedplan](security/SEED_OWNER_PLAN.md).

Argon2-Arbeitsbereich (#147): vorhandenen SecretWorkspace<Block> verwenden, damit
auch der innere Vec-Descriptor vor Allokation gesperrt ist; Blockpayload vor
Default-Initialisierung und privater Verarbeitung vollständig sperren. Nur konkreter
geprüfter Wiping-Drop-Marker; Parameter, Blockzahl, Profile, Parallelität und Bytes
unverändert. Reale Descriptor-/Payload-/Move-/Sperrfehlerprüfungen und unabhängige
KATs sind erforderlich. Provider-interne Blockkopien, Prehash/Blake2/Rayon-Stacks
und übrige R6/R7/R8-Grenzen bleiben offen; kein vollständiger Argon2-Schutz.
Siehe [Argon2-Plan](security/ARGON_WORKSPACE_OWNER_PLAN.md).

R7-Terminaleingabe: Linux liest mit rustix direkt in vorab gesperrte SecretBytes;
Windows verwendet gesperrten Record-/UTF16-/UTF8-Speicher des Callers. Kein privater
console-Key-/Escape-Vec oder kompletter nativer Record als gewöhnliche Wertkopie.
Native Ausrichtung/Größe innerhalb der geschützten Allokation prüfen; auch Padding
vor sicherem Zugriff/Rückgabe/Unwind vollständig volatil überschreiben. Ungültige
UTF8/UTF16-Eingaben strikt ablehnen, Wiederholungen und ganzes Backspace begrenzen;
Prompt erst nach Sperren/Modus setzen, normale Erfolg-/Fehlerwege prüfen Restore.
Native Linux-PTY-/Windows-Eingabetests sind Abnahmevoraussetzung. Andere Plattform-
Provider, Betriebssystemqueues, GUI/echte IME, private Skalare/Compiler/Stack/Register
und vollständiger Prozess-/Dump-/Isolationsschutz bleiben offen. Keine neue
ungeschützte Ersatzroute. Siehe [Terminalplan](security/TERMINAL_INPUT_PLAN.md).

Terminalmodus über Bestätigung und Wiederholung durchgehend halten. Linux prüft
Flags/Read-Timing vor erstem Prompt erneut; auf Fehler/Abbruch/Unwind wartende Reste
mit TCSAFLUSH verwerfen, bevor Echo zurückkehrt. Erfolgreicher Abschluss bewahrt
Typeahead. Windows prüft echte Eingabefähigkeit statt nur GetConsoleMode-Bits und
öffnet vor Privateingabe ein eigenes vorhandenes CONIN$-Read/Write-Handle für die
Fehlerbereinigung und Modussteuerung; Modus über eigenes und ursprüngliches Handle
nachprüfen. Auch gewöhnliche Read-only-Stdin-Handles unterstützen. Flush-
Fehler melden und dann keinen stillen Echo-Restore ausführen. Keine ACL-/Token-/
Nutzerrechteänderung. Später nach Abschluss eintreffende Eingaben sind nicht damit
abgedeckt. Microsoft: [Flush-Vertrag](https://learn.microsoft.com/en-us/windows/console/flushconsoleinputbuffer),
[Standard-/CONIN$-Handles](https://learn.microsoft.com/en-us/windows/console/console-handles).

R6/R8-Festowner: Hashausgabe, HKDF-PRK und -Ergebnis direkt in exakt großen
vorab gesperrten SecretBytes über eine längengeprüfte mutable Output-Leihsicht
befüllen; denselben Owner zurückgeben, keinen privaten typisierten Ausgabe-Vec
oder Arraywert anlegen. HMAC-Zustand/-Scratch und Archiv-Framing/Eintragsdatensätze
verwenden vorhandene SecretWorkspace mit vor Allokation gesperrtem innerem
Pufferdescriptor. Nur konkrete geprüfte Drop-Marker; Fehler vor privater Nutzung,
Wipe vor Unlock erhalten. Native Tests müssen tatsächliche innere Descriptor- und
Payloadsperren vor Verarbeitung/nach Owner-Moves prüfen. Keine vollständige
Provider-/Compiler-/Prozessschutzzusage; übrige R6/R7/R8-Grenzen bleiben offen.
Siehe [Festownerplan](security/FIXED_WORKSPACE_OWNER_PLAN.md).

R8 Parser-Schutzrecord: Den leeren LockedRange zunächst in einem stabil gesperrten
SecretState halten, dann direkt dort akquirieren. Aktive/partielle Records nicht
überschreiben; Metadatenfehler vor Payload-Nutzung ablehnen. Scratch-Wipe erfolgt
weiter vor Payload-Unlock/Freigabe; der Record-Drop löscht seine Felder noch unter
Metadatensperre. Der nachfolgende Parserzustandsschritt ergänzt Parser-/Scratch-
Descriptor und SliceRead/Index/Tiefe; Shared Registry und Compilertransit bleiben
offen. Keine vollständige Parser-/Transitzusage.
Siehe [Plan](security/PARSER_PROTECTION_OWNER_PLAN.md).

R8 Parserzustand: Den ausschließlich öffentlich leeren konkreten SliceRead-Parser
im bestehenden SecretState sperren, danach seinen eingebetteten Scratch-Vec
reservieren und dessen volle Kapazität schützen. Erst dann Quelle/Index direkt
im Parser binden. Synchroner Einmalscope; aktive/wiederverwendete Zustände,
ungeeignete Kapazität, erweiterte Zahlenmodi und deaktivierte Rekursionsgrenze
verweigern. SliceRead-
Scratch und iterativer IgnoredAny-Stack sind durch Eingabelänge begrenzt; letzterer
ist nicht auf Rekursion128 beschränkt. Eingabelänge+128 bleibt konservativ.
Private Fehlerpositionen vor Heap-Speicherung verwerfen und nicht nachtragen;
öffentliche Diagnose/Klassifikation erhalten. Der konkrete Parser-Drop wischt
Scratch vor Unlock/Free, SecretState danach gesamten Inlinezustand vor Unlock.
Keine Zusage über beliebige Besucher-Rückgaben, Fehlerkategorie, Providerinternas,
GUI/Prozessschutz, andere Owner oder Scalar-/Compiler-/Stacktransit. Native Tests
müssen Sperre vor Allokation/Bindung, Moves, Wipe/Unwind und echte Verweigerung
belegen. Siehe [Parserzustandsplan](security/PARSER_STATE_OWNER_PLAN.md).
