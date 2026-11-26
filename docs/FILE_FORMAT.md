# Format verschlüsselter Dateien (`.pqkf`) / Encrypted file format (`.pqkf`)

> DE: Format v2 ist im Rust-Core umgesetzt. Über die Kommandozeile ist davon die **Faktordatei** nutzbar (`--factor-file`) sowie mehrere Empfänger (`--to` mehrfach, `--with-passphrase`); nur dann entsteht v2. Dieses Dokument beschreibt v1. Siehe [V2_DRAFT.md](V2_DRAFT.md).
> EN: Format v2 is implemented in the Rust core. From the command line the **factor file** is usable (`--factor-file`) as well as several recipients (repeated `--to`, `--with-passphrase`); only then v2 is written. This document describes v1. See [V2_DRAFT.md](V2_DRAFT.md).
> DE: Mit `--sign-with` entsteht Format **v3** (v2 plus Absender-Signatur, #44): [V3_SIGNED.md](V3_SIGNED.md).
> EN: With `--sign-with` format **v3** is written (v2 plus sender signature, #44): [V3_SIGNED.md](V3_SIGNED.md).

**DE** | [EN](#english)

Eine `.pqkf`-Datei enthält immer ein kleines Archiv: **Einzeldatei** = Archiv mit genau einem
Eintrag, **Ordner** = Archiv mit allen Einträgen. So gibt es nur ein Format und einen Parser.
Datei- und Ordnerverschlüsselung ist bewusst **nicht** über die REST-API verfügbar.

## Aufbau

```
Header (Klartext, vollständig authentifiziert)
  Magic "PQKFENC\0" (8) | Version u16 = 1 | Inhalt u8 (1 Datei, 2 Ordner)
  Modus u8 (1 Passphrase, 2 Empfänger) | Blockgröße u32 = 65536 | Nonce-Präfix (7)
  Modus Passphrase: m u32 | t u32 | p u32 | Salt-Länge u8 (16–64) | Salt
  Modus Empfänger : KEM u8 (1/2/3 = ML-KEM-512/768/1024) | Empfänger-ID (32)
                    | KEM-Chiffrat-Länge u16 (exakt) | KEM-Chiffrat
  Wrap-Nonce (12) | eingepackter Dateischlüssel (48)
Verschlüsselter Strom (STREAM, AES-256-GCM, Blöcke à 64 KiB + 16 Byte Tag)
  Klartext = Archiv:
    Ordner : 1 | Pfadlänge u16 | Pfad
    Datei  : 2 | Pfadlänge u16 | Pfad | Größe u64 | Inhalt | SHA3-256(Inhalt)
    Ende   : 0 | Anzahl Einträge u64
```
Alle Zahlen Little Endian; Pfade UTF-8, Trenner „/“.

## Schlüssel

- **Dateischlüssel:** pro Verschlüsselung neu, 256 Bit aus dem OS-CSPRNG; ebenso das Nonce-Präfix.
- **Passphrase:** Argon2id(Passphrase, Salt) → Packschlüssel → AES-256-GCM(Dateischlüssel).
- **Empfänger:** ML-KEM-Kapselung an den öffentlichen Schlüssel aus der Schlüsseldatei des
  Empfängers → HKDF-SHA3-256 (Salt = KEM-Chiffrat, Info = `PQKeep/file/v1/kek\0` ‖
  Empfänger-ID) → Packschlüssel → AES-256-GCM(Dateischlüssel). Empfänger-ID = Schlüssel-ID
  (SHA3-256 des öffentlichen Schlüssels); `inspect` zeigt sie ohne Schlüssel an.
- **AAD:** Der eingepackte Schlüssel ist an alle Header-Felder davor gebunden (das KEM-Chiffrat über
  HKDF). Jeder Strom-Block trägt SHA3-256 des **gesamten** Headers als AAD.

## Sicherheit beim Entschlüsseln

- Klartext gelangt nur in eine eigene Temporärdatei bzw. einen Temporärordner neben dem Ziel.
  Veröffentlicht wird erst nach vollständiger Prüfung: alle Blöcke, Endmarke, Prüfsummen, Anzahl,
  Pfade, nichts nach dem Ende. Bei jedem Fehler wird die Temporärausgabe entfernt; das Ziel
  entsteht nie (keine Teilausgabe).
- Vorhandene Ziele werden nie überschrieben (auch kein leerer Ordner).
- **Pfadregeln:** keine leeren Teile, kein `.`/`..`, keine absoluten Pfade, kein `\`, `:`,
  `< > " | ? *`, keine Steuerzeichen, keine Windows-reservierten Namen (`CON`, `PRN`, `AUX`, `NUL`,
  `COM1–9`, `LPT1–9`, auch mit Endung), kein Leerzeichen/Punkt am Ende, Teil ≤ 255 Byte,
  Pfad ≤ 4096 Byte, Tiefe ≤ 64, höchstens 1 000 000 Einträge. Doppelte Pfade werden auch bei
  anderer Groß-/Kleinschreibung abgelehnt, ebenso Einträge unterhalb einer Datei.
- Symlinks, Geräte und Pipes werden nie angelegt. Linux: Dateien `0600`, Ordner `0700`.
- **Warum so streng:** Im Empfänger-Modus kann jeder mit dem öffentlichen Schlüssel eine korrekt
  verschlüsselte Datei bauen. Der Parser muss bösartige Archive deshalb auch nach erfolgreicher
  Entschlüsselung abweisen (Tests: `tests/files_malicious.rs`).

## Beim Verschlüsseln

- Ordner werden rekursiv und sortiert gelesen; Symlinks werden nie verfolgt.
- Übersprungen und im Bericht gemeldet: Symlinks, Geräte/Pipes/Sockets, Namen ohne gültiges UTF-8,
  nicht portable Namen (gleiche Regeln wie oben).
- Ändert sich eine Datei während des Lesens (Größe stimmt nicht), wird abgebrochen.
- Die Ausgabe wird atomar geschrieben (Temporärdatei, `fsync`, Veröffentlichen ohne Überschreiben).

## Mehrere Quellen (Mehrfachauswahl)

- **Ein Container** (`pqkeep encrypt a b Ordner -o auswahl.pqkf`, `files::encrypt_many`): kein neues
  Format – Inhalt „Ordner“, die obersten Einträge sind die gewählten Dateien und Ordner (diese samt
  Inhalt). Entschlüsselt entsteht ein Ordner. Gleiche Namen (ohne Groß-/Kleinschreibung) brechen vorab
  ab; eine gewählte Verknüpfung wird übersprungen und gemeldet. Alles oder nichts.
- **Jede einzeln** (`--each`): je Quelle eine eigene `.pqkf` mit eigenem Dateischlüssel und – im
  Passphrase-Modus – eigenem Salz und eigener Argon2id-Ableitung (ca. 1–2 s je Datei mit „standard“).
  Die Passphrase wird nur einmal eingegeben; Fehler einer Datei halten die übrigen nicht auf.
- `decrypt` mit mehreren Dateien: dieselbe Passphrase bzw. derselbe Schlüssel für alle; gemischte
  Schutzarten brechen vorab ab. `--rename` wählt bei belegtem Ziel einen freien Namen. Höchstens 1000
  Quellen pro Aufruf.

## Zufällige äußere Namen (#315)

- `encrypt --random-name` bzw. `--privacy high` gibt der `.pqkf` einen zufälligen Namen neben der
  Quelle: 128 Bit aus dem Betriebssystem-Zufall als 26 Zeichen Base32 (Kleinbuchstaben, `a–z2–7`)
  plus `.pqkf`, z. B. `k7f3q9…x2.pqkf`. **Kein Formatwechsel** (v1/v2/v3 unverändert).
- Der Originalname steht ohnehin verschlüsselt im Archiv: bei einer Datei der eine Eintrag; ein
  **Ordner** wird mit seinem Namen als oberstem Eintrag verschlüsselt (wie ein Container mit einer
  Quelle); ein **Container** (mehrere Quellen ohne `--each`) legt alles unter einen obersten Ordner mit
  dem Namen aus `--out` (ohne `.pqkf`) – die Datei selbst bekommt trotzdem einen zufälligen Namen im
  Ordner von `--out`. Mit `--each` bekommt jede Quelle einen eigenen zufälligen Namen. Ohne Container
  schließen sich zufälliger Name und `--out` aus.
- `decrypt` stellt den Originalnamen **neben der Quelle** her: automatisch, wenn der Name die
  zufällige Form hat und kein `--out` angegeben ist, sonst mit `--original-name` (schließt `--out`
  aus). Es gelten dieselben Pfadregeln wie immer; bei einer Datei muss der Name ein einzelner
  portabler Name sein, bei einem Ordner müssen alle Einträge unter **einem** obersten Ordner liegen
  (sonst Meldung „kein einzelner Originalname“, nichts entsteht). Nie überschreiben; `--rename` wählt
  einen freien Namen. Temporärausgaben heißen dabei nach der Quelle.
- `inspect` zeigt nur den Header (ohne Namen); `list` zeigt die Archivnamen erst nach dem Entsperren.
- Grenzen: Größe und – bei vielen Dateien – die Anzahl der `.pqkf` bleiben sichtbar (Padding folgt im
  Formatentwurf #316). Menü und Kontextmenü (Terminal und Fenster, einzeln und mehrfach) fragen
  beim Verschlüsseln nach der Stufe „Privatsphäre hoch“; das Kontextmenü entschlüsselt zufällig
  benannte Dateien unter dem Originalnamen.

## Datenstrom (Format v4, #83)

Inhaltstyp 3 „Strom“: beliebige Daten unbekannter Länge (z. B. aus einer Pipe) ohne Archiv, nur in
Format v4 ([V4_DRAFT.md](V4_DRAFT.md)). Header wie v2 mit Version 4, Optionsbits und Schlüsselbindung;
der Klartext endet mit einem Abschluss-Block (Nutzlänge, Füllung, `PQKFEND\0`), der beim Entschlüsseln
geprüft und nie ausgegeben wird. Abschneiden – auch genau an einer Blockgrenze – wird immer erkannt.
Entschlüsselt wird nur in eine Datei (keine Teilausgabe). Ältere Versionen melden „nicht unterstützt“.
Kommandozeile: `encrypt --stdin --out …` bzw. `--stdout` ([SERVER.md](SERVER.md)).

## Grenzen

- Die ungefähre Gesamtgröße ist sichtbar (Größe der `.pqkf`-Datei).
- Zeitstempel, Eigentümer und Rechte werden nicht übernommen, nur Inhalt und Struktur.
- Originale werden nicht gelöscht (sicheres Löschen ist auf SSDs unzuverlässig).
- Zwischen Prüfen und Öffnen einer Quelldatei könnte ein lokaler Angreifer sie gegen einen Symlink
  tauschen (TOCTOU); das betrifft nur Angreifer mit Schreibrechten im Quellordner.
- Ordner werden per „Prüfen + Umbenennen“ veröffentlicht; ein exakt gleichzeitig angelegtes Ziel
  wäre ein theoretisches Rennen (unter Windows schlägt das Umbenennen dann fehl).
- Speicherbedarf konstant (etwa zwei Blöcke), unabhängig von der Dateigröße.

---

## English

A `.pqkf` file always contains a small archive (single file = one entry, directory = all entries).
Not available via the REST API.

**Layout:** plaintext header (magic `PQKFENC\0`, version 1, content type, mode, chunk size 65536,
7-byte nonce prefix, mode data — Argon2id parameters and salt, or ML-KEM set, recipient ID and KEM
ciphertext — wrap nonce and 48-byte wrapped file key), followed by a STREAM-encrypted archive
(dir / file with size and SHA3-256 / end with entry count). Little endian; UTF-8 paths with "/".

**Keys:** fresh random 256-bit file key and nonce prefix per encryption. Passphrase mode wraps it
with Argon2id; recipient mode with ML-KEM → HKDF-SHA3-256 (salt = KEM ciphertext, info = domain tag ‖
recipient ID). The wrapped key is bound to all preceding header fields; every stream chunk carries
SHA3-256 of the whole header as AAD. `inspect` shows mode and recipient ID without a key.

**Decryption safety:** plaintext only goes to our own temporary file/directory; publishing happens
after full verification (chunks, last flag, checksums, count, paths, nothing after the end); on any
error the temporary output is removed and the target never appears. Existing targets are never
overwritten. Strict path rules (no `..`, absolute paths, `\`, `:`, reserved Windows names, control
characters, trailing space/dot, length/depth/entry limits, case-insensitive duplicates, entries
below a file). No symlinks/devices are ever created; Linux modes 0600/0700. This strictness is
needed because in recipient mode anyone with the public key can craft a correctly encrypted file.

**Encryption:** recursive, sorted, symlinks never followed; symlinks, special files, non-UTF-8 and
non-portable names are skipped and reported; a file changing while being read aborts the operation;
output is written atomically.

**Several sources:** one container (`encrypt a b folder -o selection.pqkf`, `files::encrypt_many`) uses
no new format – content "directory" whose top-level entries are the selected files and folders;
equal names (ignoring case) abort up front, a selected symlink is skipped; all or nothing. `--each`
writes one `.pqkf` per source with its own file key and, in passphrase mode, its own salt and
Argon2id derivation (about 1–2 s per file with "standard"); the passphrase is entered once and a
failing file does not stop the others. `decrypt` with several files uses the same passphrase or key
for all; mixed protection aborts up front. `--rename` picks a free name; at most 1000 sources.

**Random outer names (#315):** `encrypt --random-name` or `--privacy high` gives the `.pqkf` a
random name next to the source: 128 bits of OS randomness as 26 base32 characters (lower case,
`a–z2–7`) plus `.pqkf`. **No format change.** The original name lives encrypted in the archive: the
single entry of a file; a **directory** is encrypted with its name as the top-level entry; a
**container** puts everything below one top-level directory named after `--out` (without `.pqkf`),
while the file itself still gets a random name in the directory of `--out`; with `--each` every
source gets its own random name. Outside a container a random name and `--out` exclude each other.
`decrypt` restores the original name **next to the source** – automatically if the name has the random
shape and no `--out` is given, otherwise with `--original-name` (excludes `--out`). The usual path
rules apply; a file name must be a single portable name, a directory archive must have all entries
below **one** top-level directory (else "no single original name", nothing is created). Never
overwrites; `--rename` picks a free name; temporary output is named after the source. `inspect` shows
no names; `list` shows archive names only after unlocking. Size and the number of `.pqkf` files stay
visible (padding follows in the format draft #316). Menu and context menu (terminal and windows,
single and several files) ask for the level "privacy high" when encrypting; the context menu
decrypts randomly named files under their original name.

**Data stream (format v4, #83):** content type 3 "stream" holds arbitrary data of unknown length
(e.g. from a pipe) without an archive, format v4 only ([V4_DRAFT.md](V4_DRAFT.md)): v2 header with version
4, option bits and key commitment; the plaintext ends with a trailer (payload length, padding,
`PQKFEND\0`) that is checked and never output. Truncation – also exactly at a chunk boundary – is always
detected; decryption goes into a file only; older versions report "unsupported". Command line:
`encrypt --stdin --out …` or `--stdout` ([SERVER.md](SERVER.md)).

**Limitations:** approximate total size is visible; timestamps/ownership/permissions are not kept;
originals are not deleted; a local attacker with write access to the source directory could swap a
file for a symlink between check and open (TOCTOU); directory publishing is check + rename; memory use
is constant.


## Archivliste / Archive listing (#117)

DE: `pqkeep list` verwendet unveränderte v1/v2-Parser und prüft vollständig, ohne zu extrahieren.
Die zusätzlichen Listengrenzen (10.000 Einträge/16MiB Pfadbytes) verändern das Dateiformat und die
bestehenden check/decrypt-Grenzen nicht. Geprüfte Metadaten werden begrenzt im RAM gesammelt;
die Aussage über konstante Inhaltspuffer ist keine konstante Gesamt-RAM-Garantie für Pfadlisten.
EN: Listing reuses current v1/v2 formats and full checks without extraction. Listing-only caps
(10,000 entries/16MiB path bytes) do not change formats or check/decrypt limits. Verified metadata
is buffered within caps; constant payload buffers do not imply constant total RAM for path lists.
See / siehe [LIST.md](LIST.md).
