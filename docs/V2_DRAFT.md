# Formatentwurf v2: Faktordatei und mehrere Empfänger / Format draft v2: factor file and several recipients

**DE** | [EN](#english)

> **Freigegebener Entwurf, nicht implementiert** (Stand 09.11.2026). Das produktive Format bleibt v1
> ([FORMAT.md](FORMAT.md), [FILE_FORMAT.md](FILE_FORMAT.md)). Ein Entwurf für U0 (#39, zweiter Faktor) und
> U2 (#45, mehrere Empfänger) zusammen, damit es **einen** Formatwechsel gibt statt zwei.
> TPM/FIDO2 sind ausgelagert (Recherche-Issue #89); ihre Nummern bleiben reserviert.

## Ziele

- **Faktordatei (U0):** Öffnen nur mit Passphrase **und** einer Datei mit 32 Zufallsbytes. Wer nur die
  verschlüsselte Datei stiehlt, kann die Passphrase nicht offline erraten.
- **Mehrere Empfänger (U2):** Eine `.pqkf` für bis zu 64 öffentliche Schlüssel; jeder öffnet mit seinem
  eigenen privaten Schlüssel, kein geteiltes Passwort.
- Beides kombinierbar: ein Passphrase-Zugang (optional mit Faktor) plus Empfänger.

## Entscheidungen (D1–D4) – vom Maintainer am 09.11.2026 wie vorgeschlagen bestätigt

| Nr. | Frage | Entscheidung | Verworfene Alternative |
|---|---|---|---|
| D1 | Empfänger-IDs im Header | **sichtbar** (wie v1): eigener Zugang wird sofort gefunden | verborgen: Probe-Entschlüsselung aller Zugänge (mehr Privatsphäre, bis zu 64 KEM-Operationen) |
| D2 | Passphrase und Empfänger in einer Datei | **erlaubt** (z. B. eigener Zugang + Admin-Schlüssel) | getrennt: entweder Passphrase oder Empfänger |
| D3 | Wann wird v2 geschrieben? | **nur wenn nötig** (Faktor, mehrere Zugänge); sonst weiter v1 – ältere Versionen bleiben lesefähig | immer v2 |
| D4 | Faktordatei mit zu offenen Rechten (Linux) beim Lesen | **ablehnen** (wie SSH bei Schlüsseldateien) | nur warnen |

## Faktordatei

- Genau **32 rohe Bytes** aus dem OS-CSPRNG, eigener Befehl zum Erzeugen; nie automatisch neu erzeugt.
- Lesen: höchstens 33 Bytes, nur reguläre Dateien (keine Links/Geräte), alles außer exakt 32 → Fehler.
- Erzeugen ohne Überschreiben, Linux `0600`. Windows: ACL-Prüfung ohne `unsafe` nicht möglich (Grenze).
- Kein globaler „Pepper“, kein Hash beliebiger Dateien, keine Textverarbeitung.

## Schlüssel und Ableitung

```text
D      = "PQKeep/file/v2\0" bzw. "PQKeep/key/v2\0"
P      = UTF-8(NFKC(Passphrase)),  F = Faktordatei (32 Byte) oder leer,  S = Salt (32 Byte, 16..64 gelesen)
B      = Argon2id v0x13(P, salt=S, secret=F, associated_data=D || "argon2\0", m, t, p, 32)
Wpass  = HKDF-SHA3-256(salt=S, IKM=B, info=D || "wrap/passphrase\0" || U8(faktor), 32)
(ss,ct)= ML-KEM-Kapselung an den Empfänger
Wrec   = HKDF-SHA3-256(salt=ct, IKM=ss, info=D || "wrap/recipient\0" || Empfänger-ID[32], 32)
C      = neuer Dateischlüssel (32 Byte), je Zugang eingepackt: AES-256-GCM(W, nonce_i, C, WrapAAD(i))
```

KDF-Grenzen wie v1 (64 MiB–1 GiB, t 3–10, p 1–16), vor der Ableitung geprüft. Argon2id-Secret und
Associated Data sind in RFC 9106 definiert; unsere Crate unterstützt beides (AD ≤ 32 Byte).

## Aufbau `.pqkf` v2

```text
M  = "PQKFENC\0" || U16(2) || U8(inhalt 1/2) || U32(65536) || nonce_prefix[7] || U8(n) || zugang_1..n
Passphrase-Zugang = U8(1) || U8(faktor 0/1) || U32(m) U32(t) U32(p) || U8(len S) || S || nonce[12]
Empfänger-Zugang  = U8(2) || U8(kem 1/2/3) || ID[32] || KEM-Chiffrat (768/1088/1568) || nonce[12]
reserviert        = U8(3) TPM, U8(4) FIDO2  → in v2 „nicht unterstützt“
H  = M || hülle_1..n (je 48 Byte)
WrapAAD(i)   = D || "aad/wrap\0" || L(M) || U8(i)
Strom-AAD    = SHA3-256(H)        (wie v1; danach der unveränderte STREAM-Archivinhalt)
```

Zahlen Little Endian, `L(x)` = U32-Länge + Bytes. Regeln: 1–65 Zugänge; höchstens ein
Passphrase-Zugang, nur an erster Stelle; höchstens 64 Empfänger mit **streng aufsteigender ID**
(kanonisch, keine Doppel); Header ≤ 256 KiB (64 Empfänger mit ML-KEM-1024 ≈ 105 KiB).
Jede Hülle bindet das ganze M und ihren Index; der Inhalt bindet den Header samt **aller** Hüllen –
ein Zugang kann weder entfernt noch vertauscht werden, ohne dass das Öffnen scheitert.

## Schlüsseldatei `*.key.json` v2

Nur mit Faktordatei (D3). Felder wie v1, `format_version: 2`, zusätzlich `kdf.factor: "file-32"`.
Header-Kodierung wie v1 mit Version 2 und angehängtem Faktorbyte; Schlüssel des AES-256-GCM =
Wpass mit `D = "PQKeep/key/v2\0"`, also HKDF-SHA3-256(S, B, `PQKeep/key/v2\0wrap/passphrase\0` || U8(faktor))
– dieselbe Ableitung wie beim Passphrase-Zugang, getrennt nur über die Domäne (Referenz und Testwerte V07). Ein v1-Leser lehnt v2 ab
(„nicht unterstützt“), ein v2-Leser liest v1 unverändert.

## Kompatibilität und Fehler

| Fall | Ergebnis |
|---|---|
| v1-Datei | bisheriger Weg, unverändert |
| v1 und Faktordatei angegeben | Fehler (Faktor wird nie still ignoriert) |
| v2 mit Faktor, Faktordatei fehlt | Fehler **vor** Argon2id |
| falsche Passphrase/Faktordatei/falscher Schlüssel, Manipulation | einheitlich „Entschlüsselung fehlgeschlagen“, keine Ausgabe |
| reservierter/unbekannter Zugangstyp, unbekannte Version | „nicht unterstützt“ vor jeder Ableitung |
| eigener Schlüssel nicht unter den Empfängern | klare Meldung vor der Entkapselung (D1) |
| REST-API | Faktor und mehrere Empfänger dort nicht angeboten |

## Bedrohungsmodell (Ergänzung)

- Faktordatei: schützt gegen Offline-Raten der Passphrase, **solange F nicht mitgestohlen wird**.
  F neben der verschlüsselten Datei aufzubewahren hebt den Schutz auf. Verlust von F = Datenverlust.
- Mehrere Zugänge: der **schwächste** Zugang bestimmt die Sicherheit; die Passphrase-Regeln gelten
  unverändert. Einen Empfänger „entfernen“ heißt neu verschlüsseln; alte Kopien bleiben für ihn lesbar.
- Sichtbare IDs (D1) verraten, für welche Schlüssel eine Datei bestimmt ist, und verknüpfen Dateien.

## Folgeschritte

Umsetzung: #40 (U0-2 Core), #41 (U0-3 CLI/Sandbox), #46 (U2-2 Core), #47 (U2-3
CLI `--to` mehrfach) mit eigenen Plänen; Testkatalog: [V2_TESTS.md](V2_TESTS.md).

---

## English

> **Approved draft, not implemented** (2026-11-09). Production stays v1. One draft for U0 (#39, second
> factor) and U2 (#45, several recipients) so there is **one** format change instead of two. TPM/FIDO2 (#89)
> moved to a research issue; their numbers stay reserved.

**Goals:** factor file – open only with passphrase **and** a 32-byte random file (stealing the encrypted
file alone allows no offline guessing); several recipients – one `.pqkf` for up to 64 public keys, each
opens with their own private key; both combinable (one passphrase slot, optionally with factor, plus
recipients).

**Decisions D1–D4 (confirmed by the maintainer on 2026-11-09 as proposed):** D1 recipient IDs **visible** (as v1) vs. hidden with trial
decryption; D2 passphrase and recipients in one file **allowed**; D3 write v2 **only when needed** (factor or
several slots), else v1 so older versions can read; D4 factor file with too open permissions (Linux)
**rejected** (like SSH) vs. warning only.

**Factor file:** exactly 32 raw CSPRNG bytes, created by an explicit command, never recreated; read at most
33 bytes, regular files only, anything but exactly 32 fails; created without overwrite, Linux `0600`; Windows
ACL checks impossible without `unsafe` (limitation); no global pepper, no hashing of arbitrary files.

**Derivation and layout:** as in the code blocks above – Argon2id with RFC 9106 secret F and associated
data, HKDF-SHA3-256 per slot type with domain separation, one file key C wrapped per slot with AES-256-GCM.
Header `M` lists 1–65 slots (passphrase first and at most once; at most 64 recipients with strictly
ascending IDs), types 3/4 reserved (TPM/FIDO2, unsupported in v2), header ≤ 256 KiB. Each wrap binds the
whole M and its index; the stream binds the header with **all** wraps – slots cannot be removed or swapped.

**Key file v2:** only with a factor file; v1 fields, `format_version: 2`, `kdf.factor: "file-32"`, header
encoding as v1 with version 2 plus factor byte; AES-256-GCM key = Wpass with `D = "PQKeep/key/v2\0"`
(same derivation as the passphrase slot, separated by the domain only; reference and vectors V07). v1 readers reject v2, v2 readers read v1 unchanged.

**Compatibility:** see the table above (v1 unchanged; factor never silently ignored; missing factor fails
before Argon2id; uniform "decryption failed"; reserved/unknown types unsupported before derivation; clear
message if your key is not a recipient; not offered via the REST API).

**Threat model:** the factor file protects against offline guessing only while it is not stolen too; losing
it loses the data. With several slots the **weakest** slot defines security; removing a recipient means
re-encrypting. Visible IDs reveal and link recipients.

**Next:** implementation in #40, #41, #46, #47 with their own plans; test catalogue: [V2_TESTS.md](V2_TESTS.md).
