# Container-Integrität / Container integrity (#335)

Deutsch zuerst, [English below](#english).

**Stand:** 27.11.2026, Quelle `main` nach #353. **Art:** Audit (Code-Lesen) und Abgleich mit
vorhandenen Tests; keine Produktänderung. **Ergebnis:** kein ausnutzbarer Befund; Testlücken
G1–G7 werden in einem zweiten PR geschlossen, Grenzen L1–L3 bleiben dokumentiert.

## Umfang

Alle produktiven Lesepfade für `.pqkf`: `decrypt` (Datei, Ordner, Strom), `decrypt
--original-name` (`files::decrypt_original`), `check`, `list` und `inspect` – über alle Formate:
v1, v2 (mehrere Zugänge, Faktordatei), v3 (sichtbare Absender-Signatur), v4 (Strom, Füllung `PAD`,
anonyme Empfänger `ANON` – experimentell, verborgener Absender `HIDDEN_SENDER`). Nicht Teil:
Datei-Races beim Öffnen und Veröffentlichen (#338), Ressourcengrenzen und Fuzzing (#153),
Geheimnis-Lebensdauer im Speicher (#147).

## Bausteine und Belege

| Eigenschaft | Umsetzung (Code) | Beleg (Tests, Matrix) |
|---|---|---|
| Frischer Dateischlüssel je Datei | `aead::generate_key()` je Aufruf in `files/encrypt.rs` (`write_archive`, auch je Quelle bei `--each`) und `files/stream_v4.rs` | `crypto_stream::same_input_gives_different_ciphertext_with_new_key` (nur Ebene STREAM) → **G4** |
| Eindeutige Nonce | `crypto/stream.rs`: 7 Byte Zufallspräfix je Datei ‖ Zähler u32 (big endian) ‖ Kennung „letzter Block“; Zähler nur über `checked_add` | `crypto_stream::wrong_key_prefix_or_aad`; Grenze nur Code → **G7** |
| Zählergrenze | Nach Block 2^32 − 1 bricht `advance` mit `Error::Crypto` ab (Ver- wie Entschlüsseln), nie Wiederholung; Obergrenze ≈ 256 TiB | nur Code-Lesen (**G7**) |
| Hüllen der Zugänge | v1/v2: je Zugang zufällige 96-Bit-Nonce unter einmaligem KEK (Salz bzw. KEM-Chiffrat je Datei); v4 eigene Domäne `PQKeep/file/v4\0`; anonyme Zugänge eigener HKDF-Info | `files_v2_tamper::c04_*`, `files_anonymous`, QA1-FMT-004/-013 |
| Header als AAD | Strom-AAD = SHA3-256 des **neu kodierten** Headers (`FileHeader::stream_aad`, `HeaderV2::stream_aad`); daher muss der Parser kanonisch sein | v2: Fuzzer `pqkf_header_v2` verlangt `encode == gelesene Bytes`; v1: Fuzzer `pqkf_header` prüft nur erneutes Kodieren → **G1**; Byte-Kippen v1/v2 in `files_tamper_keys`, `files_v2_tamper` (teils Stichproben, QA1-FMT-003) → **G2** |
| Schlüsselbindung | v3 `commit` im Absenderblock, v4 `commit` in jedem Header, geprüft vor dem Strom (`check_commit`, `check_commit_v4`) | `files_signed`, `files_stream_v4`, QA1-FMT-010/-011 |
| Abschluss | STREAM: letzter Block mit Kennung 1, Leser erkennt ihn per Vorauslesen (`stream_io::refill`), Datei mit exakter Blockvielfacher-Länge endet mit leerem letzten Block; Archiv: Ende-Eintrag mit Eintragszahl, danach nichts (`DecryptReader::finish`); v4: Trailer `U64 ‖ U64 ‖ PQKFEND\0`, Füllung nur Nullbytes, kanonische Länge, ggf. Absenderblock | `crypto_stream::{truncated_and_appended, exact_multiple_cannot_be_cut_at_boundary, swapped_and_removed_chunks}`, `tail_v4_tests`, QA1-REC-001 |
| Prüfsumme je Datei im Archiv | SHA3-256 je Eintrag (`ArchiveReader::copy_file`), zusätzlich zur AEAD | QA1-REC-001 |
| Veröffentlichung erst nach voller Prüfung | Datei: `write_file` → Archivende, `finish`, Signatur (`verify`) → `TempOutput::publish`; Ordner: `fill_dir` → `finish` → `verify` → `publish`; Strom: `copy_payload` (Trailer, ggf. verborgener Absender) → kürzen → `verify` → `publish`; Originalname: gleiche Funktionen, dann `publish_child` | QA1-REC-007/-008/-012, `files_output`, `files_original` |
| Keine Ausgabe bei Fehler | `TempOutput` entfernt bei `Drop` nur die eigene Temporärausgabe (`.name.tmp-…`, Linux 0600); das Ziel erscheint nie | QA1-REC-008/-009/-010 |
| `check`/`list` | `scan::read` liest vollständig wie `decrypt` (Archivende, Trailer, Signatur); `list` gibt Einträge nur nach Erfolg zurück | `files_check`, `files_list`, QA1-REC-004 |
| Signatur v3 / verborgener Absender | v3: Hash über Header ‖ Chiffrat, Signatur am Dateiende, Prüfung vor dem Veröffentlichen; v4 verborgen: Hash über Klartext in gesperrtem Speicher, Prüfung im Trailer vor dem Veröffentlichen | `files_signed`, `files_hidden_sender`, QA1-FMT-010/-014 |

## Matrix Format × Pfad

✔ = Schutz im Code und Test vorhanden; ◐ = Schutz im Code, Test lückenhaft (Lücke in Klammern);
— = Pfad gibt es für dieses Format nicht.

| Format | decrypt Datei/Ordner | decrypt Strom | --original-name | check | list |
|---|---|---|---|---|---|
| v1 | ✔ (G1) | — | ✔ | ✔ | ✔ |
| v2 | ✔ | — | ✔ | ✔ | ✔ |
| v3 | ◐ (G2, G3) | — | ◐ (G2) | ✔ | ◐ (G2) |
| v4 Datei/Ordner (PAD/ANON/HIDDEN) | ◐ (G2, G3, G5) | — | ◐ (G2) | ✔ | ◐ (G2) |
| v4 Strom (auch PAD/HIDDEN) | — | ◐ (G3, G5) | abgewiesen ✔ | ✔ | nur Bytes ✔ |

Alle Pfade: Abbruch durch Kill (G6), Frische (G4), Zählergrenze (G7).

## Lücken (Tests folgen in PR 2)

- **G1** v1-Header-Fuzzer prüft nur, dass erneutes Kodieren stabil ist, nicht `encode == gelesene
  Bytes` wie bei v2. Da die AAD aus dem neu kodierten Header entsteht, soll auch v1 strikt
  kanonisch belegt sein (Fuzz-Ziel und Test).
- **G2** Jedes Header-Byte kippen ist für v1 (`check`) belegt, für v2 teils Stichproben, für v3/v4
  nicht vollständig – und nicht für alle Pfade (`decrypt`, `check`, `list`, `--original-name`).
- **G3** Blöcke tauschen, doppeln, entfernen und an jeder Blockgrenze abschneiden ist nur auf
  Ebene STREAM getestet; auf Dateiebene fehlen Archiv und Strom mit Füllung bzw. verborgenem
  Absender, Abschneiden **im** Trailer und ein Block aus einer zweiten Datei.
- **G4** Frische nur auf Ebene STREAM: zweimal dieselbe Quelle soll auch auf Dateiebene anderen
  Präfix, andere Schlüsselbindung und anderes Chiffrat ergeben (v1–v4).
- **G5** Fehlerpläne beim Entschlüsseln (QA1-REC-008) decken v1/v2 ab; v4-Strom und v4-Archiv mit
  Füllung bzw. verborgenem Absender fehlen.
- **G6** Kill während `decrypt` (QA1-REC-003): Ziel darf nie erscheinen; ein Temporärrest muss
  beim nächsten Lauf erkannt werden (Linux).
- **G7** Zählergrenze nur durch Code-Lesen belegt; ein Test bräuchte einen Test-Zugang in
  `src/crypto` – erst nach #147, um dessen Umbau nicht zu stören.

## Hinweis (kein Befund)

- `fill_dir` summiert `report.bytes` ohne `checked_add`, `scan::directory` mit. Ein Überlauf
  bräuchte 2^64 tatsächlich gelesene Bytes, ist also nicht erreichbar; Angleichen optional (eigene
  Freigabe, Produktivcode).

## Grenzen (bleiben)

- **L1** Nach Kill, Absturz oder Stromausfall kann **temporärer Klartext** (versteckter Name,
  Linux 0600) bleiben; es gibt keine sichere Löschung. Er wird nie unter dem Zielnamen
  veröffentlicht.
- **L2** Veröffentlichung von Ordnern sowie der Weg ohne Hardlinks (z. B. FAT) sind „prüfen und
  umbenennen“, nicht atomar → #338.
- **L3** Ältere, schon veröffentlichte Programmversionen werden nicht ausgeführt (QA1-FMT-008);
  sie melden neue Formate laut Code als „nicht unterstützt“.

---

## English

**Status:** 2026-11-27, source `main` after #353. **Kind:** audit (code reading) and comparison
with existing tests; no product change. **Result:** no exploitable finding; test gaps G1–G7 are
closed in a second PR, limits L1–L3 stay documented.

**Scope:** all productive read paths for `.pqkf` – `decrypt` (file, directory, stream), `decrypt
--original-name`, `check`, `list`, `inspect` – across v1, v2 (several slots, factor file), v3
(visible sender signature) and v4 (stream, padding `PAD`, anonymous recipients `ANON` –
experimental, hidden sender `HIDDEN_SENDER`). Not covered: file races when opening and
publishing (#338), resource limits and fuzzing (#153), secret lifetime in memory (#147).

**Building blocks:** fresh file key per file (`aead::generate_key()` per call, also per source
with `--each`); nonce = 7-byte random prefix per file ‖ u32 counter (big endian) ‖ last flag, the
counter only advances via `checked_add` and aborts after chunk 2^32 − 1 (≈ 256 TiB) instead of
repeating; slot wraps use random 96-bit nonces under single-use KEKs (per-file salt or KEM
ciphertext), v4 with its own domain; the stream AAD is SHA3-256 of the **re-encoded** header, so
the parser must be canonical (v2 fuzzer requires `encode == bytes read`, v1 fuzzer only checks
stable re-encoding → G1); key commitment (v3 sender block, every v4 header) is checked before the
stream; end detection via the last flag (read-ahead; an exact chunk multiple ends with an empty
last chunk), the archive end entry with entry count and nothing after it, and for v4 the trailer
(zero-only canonical padding, optional sender block); per-entry SHA3-256 in archives; publication
only after complete verification (archive end, `finish`, signature) via `TempOutput`, which on
`Drop` removes only its own temporary output (`.name.tmp-…`, Linux 0600) – the target never
appears; `check`/`list` read completely like `decrypt`, `list` returns entries only on success;
v3 signature over header ‖ ciphertext, hidden sender over the plaintext hash, both verified before
publishing. Evidence: tests and attack cases listed in the German table above.

**Matrix:** v1 and v2 are covered on all paths (v1 header canonicality G1); v3, v4 files/
directories and v4 streams are protected in code, with test gaps G2 (every header byte on all
paths), G3 (file-level chunk swap/duplicate/remove, cuts at every boundary and inside the trailer,
a chunk from a second file) and G5 (fault plans for v4); all paths: kill during decrypt (G6),
freshness at file level (G4), counter limit (G7, code reading only – a test needs a test hook in
`src/crypto`, deferred until after #147).

**Note (no finding):** `fill_dir` sums `report.bytes` without `checked_add` (`scan::directory`
uses it); an overflow needs 2^64 bytes actually read and is unreachable; aligning is optional and
needs its own approval.

**Limits:** L1 after kill, crash or power loss **temporary plaintext** (hidden name, Linux 0600)
may remain – no secure deletion, never published under the target name; L2 directory
publication and the path without hard links (e.g. FAT) are check-and-rename, not atomic → #338;
L3 already released old versions are not executed (QA1-FMT-008); by code they report new formats
as "unsupported".
