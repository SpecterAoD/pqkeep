# Testkatalog v2 / Test catalogue v2

**DE** | [EN](#english)

Zu [V2_DRAFT.md](V2_DRAFT.md). `reference` = ausführbare Python-Referenz in `scripts/test_v2_*.py`
(läuft in der CI auf Linux und Windows); `planned` = **noch nicht umgesetzt**, gehört zum genannten
Folge-Issue. Referenztests prüfen Kodierung und Regeln, nicht die Sicherheit einer Rust-Umsetzung.

| ID | Fall | Soll | Phase | Status |
|---|---|---|---|---|
| V01 | Zugänge: Passphrase mit/ohne Faktor, Empfänger 512/768/1024, ungültige Werte | exakte Bytes, Ablehnung | #39 | reference |
| V02 | Header M mit einem Zugang | exakte Bytes | #39 | reference |
| V03 | 0 Zugänge, 2× Passphrase, Passphrase nicht zuerst, unsortiert, doppelt, Typ 3/4/unbekannt | Ablehnung | #39 | reference |
| V04 | 64/65 Empfänger, Headergrenze 256 KiB inklusive, Hüllenzahl falsch | Grenze inklusive, sonst Ablehnung | #39 | reference |
| V05 | Hüllen-AAD: Index, Domäne, jedes Byte von M | jeweils andere AAD | #39 | reference |
| V06 | Strom-AAD: jedes Byte jeder Hülle | jeweils andere AAD | #39 | reference |
| V07 | HKDF-SHA3-256 Passphrase (file/key × Faktor 0/1) und Empfänger | unabhängige Sollwerte | #39 | reference |
| V08 | Argon2-AD ≤ 32 Byte, Domänen getrennt von v1, alle Info-Werte verschieden | erfüllt | #39 | reference |
| V09 | Faktordatei 0/31/32/33/4096 Byte | nur genau 32 | #39 | reference |
| V10 | Katalog eindeutig, jede `reference`-Zeile hat einen Test, Links gültig | erfüllt | #39 | reference |
| C01 | Argon2id mit Secret F und AD, echte Mindestparameter | unabhängiger Vektor (z. B. argon2pure) + RFC 9106 | #40 | planned |
| C02 | Hüllen und Inhalt: AES-256-GCM-Vektoren inkl. AAD | unabhängige Vektoren, nicht nur Rundlauf | #40 | planned |
| C03 | Faktordatei fehlt/falsch/zu groß/Link/Gerät/zu offene Rechte (D4) | Fehler vor Argon2id, nie neu erzeugt | #40 | planned |
| C04 | jedes Header-/Hüllen-/Strom-Byte verändert, Zugang entfernt/vertauscht | Öffnen scheitert, keine Ausgabe | #40/#46 | planned |
| C05 | Kürzen an jeder Headerposition, Längen bis u32::MAX, 256-KiB-Budget | begrenzter Parser, keine Panik | #40/#46 | planned |
| C06 | v1↔v2-Matrix, Downgrade-Versuche, D3 (v1 wenn möglich) | wie Kompatibilitätstabelle | #40 | planned |
| C07 | Schlüsseldatei v2: alle Algorithmen, falscher Faktor, v1-Leser | Seed unverändert, v1 lehnt ab | #40 | planned |
| C08 | 1/2/64 Empfänger gemischter KEM-Stufen, eigener Schlüssel fehlt | jeder öffnet, klare Meldung | #46 | planned |
| C09 | Fuzzing JSON-/Binärparser v2 | keine Panik, begrenzter Speicher | #40/#46 | planned |
| U01 | CLI: `--factor`, Faktordatei erzeugen, `--to` mehrfach, DE/EN-Hilfe | eindeutige Bedienung | #41/#47 | planned |
| U02 | Sandbox: Faktordatei lesbar, sonst nichts zusätzlich | Landlock-Freigaben minimal | #41 | planned |
| U03 | Geheimnisse nicht in argv/Umgebung/Logs, API lehnt v2-Optionen ab | keine Offenlegung | #41 | planned |

## Ausführung

```sh
python3 -m unittest discover -s scripts -p 'test_v2_*.py' -v
```

V07-Sollwerte wurden unabhängig mit `cryptography` 41.0.7 berechnet; die Tests nutzen nur die
Standardbibliothek. Keine echten Geheimnisse oder verschlüsselten Dateien im Repository.

---

## English

Catalogue for [V2_DRAFT.md](V2_DRAFT.md). `reference` = executable Python reference in
`scripts/test_v2_*.py` (runs in CI on Linux and Windows); `planned` = **not implemented yet**, belongs to
the named follow-up issue. Reference tests check encoding and rules, not the security of a Rust
implementation. Run with the command above. V07 expected values were computed independently with
`cryptography` 41.0.7; the tests use only the standard library. No real secrets or encrypted files are
committed.
