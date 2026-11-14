# Fahrplan / Roadmap

Details zu jedem Schritt: [`SPEC.md`](SPEC.md), Abschnitt 7. Jeder Schritt braucht Plan-Freigabe, grüne Tests und die [Checkliste](CHECKLIST.md).

**Stand / status (08.11.2026):** Schritte 0–7 abgeschlossen, erste Beta [`v0.1.0-beta.1`](https://github.com/SpecterAoD/pqkeep/releases/tag/v0.1.0-beta.1) veröffentlicht; SignPath vorerst abgelehnt (erneute Bewerbung später); als Nächstes die Updates unten. / Steps 0–7 done, first beta published; SignPath declined for now (will reapply later); next: the updates below.

| Schritt | Inhalt | Ergebnis |
|---|---|---|
| 0 | Projekt-Grundgerüst, Lints, `error.rs`, CI-Rumpf, Zeilenlimit-Check | Leerer Build grün auf Linux und Windows |
| 1 | Core-Krypto: ML-KEM, ML-DSA, AES-256, Argon2id, AES-256-GCM-Container-Verschlüsselung ([CRYPTO.md](CRYPTO.md)) | Roundtrip-, Manipulations-, KAT- und Zeroize-Tests |
| 2 | `security.rs`: Passphrase-Prüfung, Entropie, Generator | Schwach abgelehnt, stark akzeptiert, Generator getestet |
| 2a | `hardening/`: Speichersperre (mlock/VirtualLock), Core-Dump-Sperre, sofortiges Nullen ([MEMORY_HARDENING.md](MEMORY_HARDENING.md)) | Sperr-/Freigabe-Tests, Best-effort bei Limit |
| 2b | Wort-Modell + Wortlisten (EFF, BIP-39, deutsche Diceware-Listen) für die Passphrase-Prüfung ([SECURITY_PASSPHRASE.md](SECURITY_PASSPHRASE.md)) | Zusammengesetzte Wörter abgelehnt, Sätze/Zufall angenommen |
| 3 | `envelope/`: JSON-Container, Metadaten, Parser-Härtung ([FORMAT.md](FORMAT.md)) | Roundtrip, Pfadkonventionen Windows/Linux, Fuzz/Property-Tests |
| 3a | `files/`: Datei- und Ordnerverschlüsselung (Passphrase oder ML-KEM-Empfänger), Streaming-AEAD, Archiv, Pfadsicherheit ([FILE_FORMAT.md](FILE_FORMAT.md)) | Roundtrip, Manipulation, bösartige Archive, keine Teilausgabe |
| 4 | `cli.rs`: Menü, Subcommands, integrierte zweisprachige Hilfe | CLI-Integrationstests, Hilfetests DE/EN |
| 5 | `api.rs`: Axum-REST-API, Härtung | HTTP-Integrationstests inkl. Auth, Limits, DoS-Schutz |
| 5a | Sandboxing Linux: Landlock (Dateipfade), Seccomp-BPF (Systemaufrufe), Profile für CLI und API | Verbotene Zugriffe scheitern, normale Abläufe funktionieren |
| 6 | CI/CD, Release-Workflow mit Signierung, Dokumentation | Grüne CI, Beta-Trockenlauf mit Verifikation |
| 7 | Abschluss-Review, erste signierte Beta | `v0.1.0-beta.1` veröffentlicht und verifiziert |

## Geplante Updates nach der ersten Beta (Details: SPEC Abschnitt 9, Issues mit Label `update`)

| Update | Inhalt | Issues |
|---|---|---|
| U0 | Zweiter Faktor als Faktordatei – Format v2 gemeinsam mit U2: [V2_DRAFT.md](V2_DRAFT.md); Core und Kommandozeile (`pqkeep factor`, `--factor-file`) sowie Menü, geführter Ablauf und Kontextmenü umgesetzt; TPM/FIDO2 als Recherche | #39–#41 |
| U1 | Digitale Signaturen mit ML-DSA-87: `sign`/`verify`, Absender-Signatur für `.pqkf` – keine qualifizierte eIDAS-Signatur; U1-1 Format `.pqsig` + Core und U1-2 `sign`/`verify` umgesetzt ([SIGNATURE_FORMAT.md](SIGNATURE_FORMAT.md)) | #42–#44 |
| U2 | Mehrere Empfänger pro Container (ML-KEM-1024 je Empfänger) – Format v2: [V2_DRAFT.md](V2_DRAFT.md); Core und Kommandozeile (`--to` mehrfach, `--with-passphrase`) umgesetzt, Menü/Kontextmenü offen | #45–#47 |
| U3 | Einrichtungs-Assistent in der Konsole, Notfall-Backup | #48–#50 |
| U4 | Kontextmenü (Rechtsklick) mit Passphrase-Dialog; U4-1 Linux, U4-2 Windows und U4-3 Fenster unter Linux und Windows, U4-4 Mehrfachauswahl sowie U4-5 Thunar umgesetzt ([INTEGRATION.md](INTEGRATION.md)) | #51–#53, #72, #92 |
| GUI | Optionale moderne grafische Oberfläche, rein in Rust, ohne Web-Technik und Netzwerk; Sicherheit vorab neu bewerten (SPEC-Änderung nötig) | #58–#65 (Label `gui`) |
| – | Spiegel-Modus für Ordner | #54 |
| – | Diceware-Generator mit gemeinfreier Wortliste | #55 |
| – | Hybrid-Verfahren (X25519 + ML-KEM) neu bewerten | #56 |
| iOS | iOS-App (ferne Zukunft): Machbarkeit, Architektur, Bedrohungsmodell | #66–#67 (Label `zukunft`) |

## Offene Punkte außerhalb des Codes

- [x] Repository öffentlich schalten (Voraussetzung für SignPath) – 07.11.2026
- [x] Bei der SignPath Foundation beworben – 08.11.2026 vorerst abgelehnt (zu wenig Sichtbarkeit)
- [ ] Später erneut bei SignPath bewerben; bis dahin bleibt das Windows-Programm unsigniert
- [x] MFA bei GitHub aktiv (SignPath bei der Bewerbung)
- [x] Ruleset auf `main` (PR, Pflicht-Checks, signierte Commits) und Schutz der Release-Tags
- [x] Secret Scanning und Push Protection aktiv
- [x] Signing-Key für Git-Tags (SSH)
