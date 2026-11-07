# Fahrplan / Roadmap

Details zu jedem Schritt: [`SPEC.md`](SPEC.md), Abschnitt 7. Jeder Schritt braucht Plan-Freigabe, grüne Tests und die [Checkliste](CHECKLIST.md).

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

## Geplante Updates nach der ersten Beta (Details: SPEC Abschnitt 9)

| Update | Inhalt | Hinweis |
|---|---|---|
| U1 | Digitale Signaturen mit ML-DSA-87: `sign`/`verify`, `[VERIFIED]`/`[INVALID]`, Absender-Signatur für `.pqkf` | Keine qualifizierte eIDAS-Signatur; Identität über Fingerabdruck bestätigen |
| U2 | Mehrere Empfänger pro Container (ML-KEM-1024 je Empfänger) | Neue Formatversion; Empfänger-IDs sichtbar oder verborgen (Entscheidung im Plan) |
| U3 | Einrichtungs-Assistent in der Konsole: Master-Passphrase, ML-KEM-1024 + ML-DSA-87, Kontextmenü, Notfall-Backup | Erneut aufrufbar, überschreibt nie ohne Bestätigung |
| U4 | Kontextmenü (Rechtsklick) mit Passphrase-Dialog | Abweichung vom Non-Goal „GUI“ – nur Dialog, Umsetzung im Plan entscheiden |
| – | Spiegel-Modus für Ordner | |
| – | Diceware-Generator (DE/EN) | Wortlisten sind seit 2b vorhanden (EFF als freigegebene Ausnahme) |

## Offene Punkte außerhalb des Codes

- [ ] Repository öffentlich schalten (Voraussetzung für SignPath)
- [ ] Bei der SignPath Foundation bewerben (erst wenn Repo öffentlich und Lizenz vorhanden)
- [ ] MFA für alle Beteiligten bei GitHub und SignPath aktivieren
- [ ] Branch Protection auf `main`, signierte Commits erzwingen
- [ ] Secret Scanning und Push Protection aktivieren
- [ ] Signing-Key für Git-Tags einrichten (SSH oder GPG)
