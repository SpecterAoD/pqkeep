# Formatentwurf v4: Privatsphäre und Strom-Modus / Format draft v4: privacy and stream mode

**DE** | [EN](#english)

> Entwurf zu #316 (Padding, anonyme Empfänger, verborgener Absender) **gemeinsam mit #83**
> (Strom-Modus: Verschlüsseln von stdin), SPEC v2.21, Abschnitt 9 U5 und S2. Beide ändern Inhalt
> bzw. Header; deshalb **ein** Versionsschema für alles. Nur Entwurf – die Umsetzung folgt in eigenen
> PRs (siehe [Umsetzung](#umsetzung)). Alles ist **optional und standardmäßig aus**: ohne Option
> bleiben v1/v2/v3 **Byte für Byte** unverändert (D3). Zufällige äußere Namen (#315) brauchen kein
> neues Format und sind bereits umgesetzt ([FILE_FORMAT.md](FILE_FORMAT.md)).

## Ziele

- **Padding** (`--pad`): die genaue Größe des Inhalts nicht verraten.
- **Anonyme Empfänger** (`--anonymous-recipients`): keine Empfänger-IDs im Klartext; Dateien lassen sich
  nicht mehr über Schlüssel-IDs einander oder Personen zuordnen.
- **Verborgener Absender** (`--hide-sender`, nur mit `--sign-with`): Absenderschlüssel und Signatur nur
  im verschlüsselten Teil; prüfen kann nur, wer die Datei öffnen kann.
- **Strom** (`encrypt --stdin`, `--stdout`; #83): Daten unbekannter Länge aus einer Pipe verschlüsseln,
  konstanter Speicher, keine Temporärdateien bei `--stdout`. Entschlüsselt wird nur in eine Datei
  (S2b verworfen, Maintainer 08.11.2026).
- Stufe `--privacy high` = zufälliger Name (#315) + Padding + anonyme Empfänger + verborgener Absender
  (soweit anwendbar); Menü und Kontextmenü bieten nur die Stufe; Voreinstellungen später über
  Profil/Einrichtung (#136, #48–#50).

## Entscheidungen (P1–P9)

Vorschläge; mit dem Merge dieses Entwurfs freigegeben (Auftrag Thomas 25.11.2026: #315 und #316
„in einem Zug bis zum Merge“). Die ausdrücklich verlangte **D1-Ausnahme** ist P4.

| Nr. | Frage | Entscheidung (Vorschlag) | Verworfene Alternative |
|---|---|---|---|
| P1 | Versionsschema | **eine** neue Version **4** mit **Optionsbits** im Header; v4 nur, wenn eine Option es verlangt (D3). Unbekannte Bits → „nicht unterstützt“ | je Option eine eigene Version (v4, v5, …): Kombinationen explodieren, #83 und #316 bräuchten getrennte Leser |
| P2 | Strom-Inhalt (#83) | neuer Inhaltstyp **3 „Strom“** (rohe Bytes, kein Archiv), nur in v4 | Strom als Archiv mit einer Datei unbekannter Größe: Archiv-Eintrag braucht die Größe vorab |
| P3 | Wo stehen Länge, Füllung und verborgener Absender? | in einem **Abschluss-Block (Trailer) am Ende des verschlüsselten Stroms**, feste Länge je nach Optionsbits; der Leser hält nur so viele Bytes zurück (konstanter Speicher) | Länge vorab im Header: bei stdin unbekannt; zweiter Durchlauf/Zurückspringen bei `--stdout` unmöglich |
| P4 | **D1-Ausnahme** | **anonyme Empfänger nur auf Wunsch** (`--anonymous-recipients` bzw. Stufe hoch); **D1 (sichtbare IDs) bleibt Standard** | immer verborgen (bis zu 64 Probe-Entkapselungen bei jeder Datei, schlechtere Fehlermeldung) |
| P5 | Anonyme Zugänge: Kyber-Stufe | **nur ML-KEM-1024** (gleiche Chiffratlänge für alle; die Stufe verrät nichts) | alle Stufen: Länge 768/1088/1568 verrät die Stufe und grenzt Empfänger ein |
| P6 | Reihenfolge anonymer Zugänge | **aufsteigend nach KEM-Chiffrat** (kanonisch, aber zufällig – verrät nichts) | aufsteigend nach ID (gibt es nicht mehr) oder beliebig (nicht kanonisch) |
| P7 | Padding-Verfahren | **PADMÉ** (Nikitin u. a. 2019) über die Länge des ganzen Klartexts; höchstens ~12 % Mehrgröße, meist < 3 %; verrät nur O(log log L) Bit | feste Blöcke (verraten mehr bei großen Dateien) oder Zufallslänge (mittelt sich über viele Dateien heraus) |
| P8 | Schlüsselbindung | `commit` (wie v3, S4) **in jeder v4-Datei** – 32 Byte, schützt Mehr-Empfänger-Dateien auch ohne Signatur gegen „verschiedene Klartexte je Empfänger“ | nur mit Signatur |
| P9 | Was signiert der verborgene Absender? | Header, **Klartext samt Füllung und die Grenze dazwischen** (`SHA3-512(H) ‖ SHA3-512(N) ‖ U64(Länge Nutzdaten) ‖ U64(Länge Füllung)`, Domäne „hidden“); ohne die Längen könnte ein Empfänger mit neu verschlüsseltem Trailer Füll-Nullbytes als signierten Inhalt ausgeben (Codex-Fund #324). Zusammen mit `commit` ist das Chiffrat damit eindeutig bestimmt | das Chiffrat (wie v3): unmöglich, weil die Signatur selbst im Chiffrat steht |

## Aufbau `.pqkf` v4

```text
M  = "PQKFENC\0" ‖ U16(4) ‖ U8(inhalt 1/2/3) ‖ U32(65536) ‖ nonce_prefix[7] ‖ U16(optionen)
     ‖ U8(n) ‖ zugang_1..n ‖ [absenderblock, nur Bit SIGNED] ‖ commit[32]
H  = M ‖ hülle_1..n (je 48 Byte)
Datei = H ‖ C ‖ [Σ, nur Bit SIGNED]
C  = STREAM wie v1–v3 (Blöcke à 64 KiB + Tag, Endmarke im letzten Block), Strom-AAD = SHA3-256(H)
Klartext von C:  N ‖ T     mit  N = Nutzdaten ‖ Füllung
```

**Optionsbits** (U16, Little Endian; alle anderen Bits müssen 0 sein, sonst „nicht unterstützt“):

| Bit | Name | Bedeutung |
|---|---|---|
| 0x0001 | PAD | Füllung nach den Nutzdaten (PADMÉ) |
| 0x0002 | ANON | alle Empfänger-Zugänge sind anonym (Typ 5) |
| 0x0004 | SIGNED | sichtbarer Absender wie v3 (Absenderblock in M, Σ am Dateiende) |
| 0x0008 | HIDDEN_SENDER | Absender und Signatur im Trailer T; schließt SIGNED aus |

Inhaltstyp 3 („Strom“) ist nur in v4 erlaubt; ein v4 ohne Optionsbit und mit Inhalt 1/2 ist ungültig
(dann muss v1/v2/v3 geschrieben werden – D3 bleibt kanonisch).

**Zugänge:** Passphrase (Typ 1) und Empfänger mit ID (Typ 2) wie v2. Neu:

```text
anonymer Empfänger-Zugang = U8(5) ‖ U8(kem = 3) ‖ KEM-Chiffrat[1568] ‖ nonce[12]
Wanon = HKDF-SHA3-256(salt = ct, IKM = ss, info = D ‖ "wrap/anonymous\0", 32)   mit D = "PQKeep/file/v4\0"
WrapAAD(i) = D ‖ "aad/wrap\0" ‖ L(M) ‖ U8(i)           (wie v2, Domäne v4)
commit     = SHA3-256(D ‖ "commit\0" ‖ Dateischlüssel)
```

Regeln: 1–65 Zugänge, Passphrase höchstens einmal und zuerst; mit ANON **nur** Typ 5 als Empfänger (kein
Mischen mit Typ 2, sonst wäre die Anonymität halb), streng aufsteigend nach Chiffrat; ohne ANON kein
Typ 5. Header ≤ 256 KiB.

**Trailer T** (am Ende des Klartexts, Länge aus den Optionsbits bekannt):

```text
T = [absender_verborgen, nur HIDDEN_SENDER] ‖ U64(länge Nutzdaten) ‖ U64(länge Füllung) ‖ "PQKFEND\0"
absender_verborgen = U8(algorithmus = 1) ‖ öffentlicher_schlüssel[2592] ‖ Σh[4627]
Nachricht_h = D ‖ "sig/hidden\0" ‖ SHA3-512(H) ‖ SHA3-512(N) ‖ U64(länge Nutzdaten) ‖ U64(länge Füllung)
Σh = ML-DSA-87.Sign(sk, Nachricht_h, Kontext "PQKeep/pqkf-sig/v1")
Füllung: lauter Nullbytes; länge Füllung = PADMÉ(|N ohne Füllung| + |T|) − (|N ohne Füllung| + |T|), ohne PAD 0
```

Der Leser prüft: Trailer vollständig vor der Endmarke des STREAM, Kennung `PQKFEND\0`, Längen addieren
sich genau zur Klartextlänge, Füllung nur Nullbytes, mit PAD genau die PADMÉ-Länge (kanonisch), ohne PAD
Füllung 0. Bei Inhalt 1/2 muss das Archiv genau vor der Füllung enden.

PADMÉ(L): `E = ⌊log2 L⌋, S = ⌊log2 E⌋ + 1, z = E − S, L' = (L + 2^z − 1) & ~(2^z − 1)`. Beispiele:
1000 → 1024 (+2,4 %), 1 000 000 → 1 015 808 (+1,6 %), 10 000 000 → 10 223 616 (+2,2 %),
1 000 000 000 → 1 006 632 960 (+0,7 %).

## Abläufe

**Verschlüsseln:** Optionen → v4 nur, wenn nötig → Dateischlüssel, `commit`, Header schreiben → Nutzdaten
streamen (bei stdin bis EOF, Zähler U64; bei HIDDEN_SENDER zugleich SHA3-512 über N) → Füllung →
Trailer → letzter Block mit Endmarke → bei SIGNED Σ anhängen. Mit `--stdout` wird direkt geschrieben
(kein Veröffentlichen, keine Temporärdatei); ein Abbruch hinterlässt eine unvollständige Datei, die beim
Entschlüsseln sicher scheitert (Endmarke fehlt). SIGPIPE: sauberer Fehler, kein Teil-Erfolg.

**Entschlüsseln / `check`:** Header → Zugänge: mit ID wie bisher (D1-Meldung „nicht für dich“ vor der
Entkapselung); mit ANON jeden Typ-5-Zugang probieren (höchstens 64 Entkapselungen + GCM, ML-KEM mit
impliziter Ablehnung liefert bei falschem Schlüssel nur Zufall) – erst danach die Meldung „kein Zugang für
diesen Schlüssel“ → `commit` prüfen → Strom entschlüsseln, die letzten |T| Bytes zurückhalten → Trailer
prüfen → ggf. Σh bzw. Σ prüfen → erst dann veröffentlichen. Inhalt 3 wird **nur in eine Datei**
entschlüsselt (Temporärdatei, am Ende auf die Nutzlänge gekürzt, dann veröffentlicht); nie nach stdout.

**`inspect`:** zeigt Version, Optionen, Inhaltstyp, Zugänge (anonyme ohne ID), bei SIGNED den
**ungeprüften** Absender, bei HIDDEN_SENDER nur „signiert (verborgen)“. Keine Länge (nur verschlüsselt).

## Kompatibilität und Fehler

| Fall | Ergebnis |
|---|---|
| keine der neuen Optionen | v1/v2/v3 unverändert, Byte für Byte |
| v4-Datei mit 0.1.0-beta.1 bis heute | „nicht unterstützt“ (unbekannte Version), nie still |
| unbekanntes Optionsbit, SIGNED + HIDDEN_SENDER, Typ 5 ohne ANON, Typ 2 mit ANON, kem ≠ 3 bei Typ 5 | „nicht unterstützt“ bzw. ungültig, vor jeder Ableitung |
| Optionsbit entfernt/gesetzt, Inhaltstyp geändert (Downgrade) | M ändert sich → WrapAAD und Strom-AAD passen nicht → „Entschlüsselung fehlgeschlagen“ |
| Strom abgeschnitten (auch genau an einer Blockgrenze) | Endmarke fehlt → „Entschlüsselung fehlgeschlagen“, keine Ausgabe |
| Daten angehängt, Blöcke vertauscht | „Entschlüsselung fehlgeschlagen“ |
| Trailer kaputt, Längen passen nicht, Füllung ≠ 0, Füllung nicht PADMÉ | ungültig, keine Ausgabe |
| verborgene Signatur ungültig / anderer Absender mit `--signer` | Fehler (Exit 7), keine Ausgabe |
| kein anonymer Zugang passt | „kein Zugang für diesen Schlüssel“ nach allen Versuchen |
| `decrypt` eines Stroms ohne Ziel bzw. nach stdout | Bedienfehler; nur in eine Datei |

## Bedrohungsmodell (Ergänzung)

- **Padding** verbirgt die genaue Größe, nicht die Größenordnung; Anzahl der Dateien, Header-Größe
  (Zahl der Zugänge) und Zeitpunkte bleiben sichtbar. Mehrfaches Verschlüsseln desselben Inhalts ergibt
  dieselbe gepolsterte Länge.
- **Anonyme Empfänger:** verbirgt, *für wen* eine Datei ist; die **Anzahl** der Zugänge bleibt sichtbar
  (Attrappen-Zugänge wären eine spätere Erweiterung). Die Anonymität stützt sich auf die
  ANO-CCA-Eigenschaft von ML-KEM (FO-Transformation mit impliziter Ablehnung; Literatur u. a. Grubbs,
  Maram, Paterson 2022 und Xagawa 2022) – vor der Umsetzung erneut prüfen und in CRYPTO.md belegen. Die
  Probe-Entkapselung kostet beim Öffnen bis zu 64 ML-KEM-1024-Operationen (Millisekunden); Zeitunterschiede
  verraten nur dem Öffnenden selbst, welcher Zugang passte.
- **Verborgener Absender:** Außenstehende sehen nicht, von wem die Datei stammt; Empfänger sehen und
  prüfen ihn. Sinnvoll vor allem mit anonymen Empfängern. Ein Empfänger kann weiterhin unter eigenem
  Namen neu verschlüsseln (wie v3).
- **Strom:** Abschneiden wird immer erkannt (STREAM-Endmarke); Teilausgabe beim Entschlüsseln gibt es
  nicht (nur Datei, Veröffentlichen nach Prüfung). Bei `--stdout` beim Verschlüsseln ist der Empfänger
  der Pipe für Abbrüche verantwortlich; die Datei bleibt dann unlesbar statt still unvollständig.

## Testkatalog (Auszug, Status „planned“)

| ID | Fall |
|---|---|
| P01 | v1/v2/v3 ohne Option Byte für Byte unverändert (KAT-Vergleich) |
| P02 | jede Kombination der Optionsbits und Inhaltstypen: Rundlauf (Datei, Ordner, Strom 0 Byte, 1 Byte, Blockgrenze ± 1, > 4 GiB per Zähler-Test) |
| P03 | Downgrade: jedes Optionsbit kippen, Version 4 → 3/2/1, Inhaltstyp ändern → Fehler, keine Ausgabe |
| P04 | Abschneiden an jeder Blockgrenze und im Trailer, Anhängen, Vertauschen |
| P05 | Trailer: falsche Kennung, Längen ± 1, Füllung ≠ 0, nicht-PADMÉ-Länge, Archiv endet vor/nach der Füllung |
| P06 | PADMÉ-Referenzwerte (unabhängiges Python-Skript) und Höchst-Mehrgröße |
| P07 | anonym: richtiger Schlüssel an jeder Position 1–64; falscher Schlüssel → Meldung erst nach allen; Mischen Typ 2/5 abgelehnt; kem ≠ 3 abgelehnt; Reihenfolge nicht kanonisch abgelehnt |
| P08 | verborgener Absender: Signatur kippen, anderer Absender, `--signer`, Header-/Klartext-Änderung, **Grenze Nutzdaten/Füllung verschoben (neu verschlüsselter Trailer)**, SIGNED + HIDDEN abgelehnt |
| P09 | `commit` falsch bei mehreren Empfängern (unterschiedliche Dateischlüssel je Hülle) → Fehler |
| P10 | `--stdin`/`--stdout`: große Ströme mit konstantem Speicher, leere Eingabe, SIGPIPE, keine Temporärdatei |
| P11 | Fuzz-Ziel `pqkf_header_v4` und Trailer-Parser (#153); Angriffskatalog QA1-FMT-* ergänzen |

## Umsetzungsstand

**Schritt 1 (Kern) umgesetzt** (`src/files/format_v4.rs`, `stream_v4.rs`; API vorläufig bis #98:
`files::encrypt_stream`, `files::encrypt_stream_to`; Entschlüsseln über `decrypt`/`check`). Präzisierungen
gegenüber dem Entwurf:
- Zugänge und Schlüsselableitungen (KEK) unverändert wie v2; nur WrapAAD nutzt die Domäne
  `PQKeep/file/v4\0`. `M` enthält Version und Optionsbits, ist also an jede Hülle und jeden Block gebunden.
- Mit `SIGNED` ist der Absenderblock bytegleich der v3-Block (Algorithmus ‖ Schlüssel ‖ `commit`), dort
  steht das v4-`commit`; die Signaturnachricht ist die von v3 (H enthält Version 4).
- `PAD`, `ANON`, `HIDDEN_SENDER` und unbekannte Bits: „nicht unterstützt“; v4 nur mit Inhalt 3.
- Der Leser hält die 24 Trailer-Bytes im gesperrten Puffer zurück; `list` zeigt bei Strömen keine Einträge,
  nur Bytes; `decrypt` unter Originalnamen ist für Ströme nicht möglich (kein Name).
- Tests: `tests/files_stream_v4.rs`, `src/files/{format_v4,stream_v4}_tests.rs`; Angriffsmatrix
  QA1-FMT-011; der Header-Fuzzer `pqkf_header_v2` deckt v4 mit ab.

**Schritt 2 (#83, Kommandozeile) umgesetzt:** `encrypt --stdin` mit `--out` (atomar) oder `--stdout` (keine
Temporärdatei, Meldungen auf stderr); Passphrase nur über `--passphrase-file` oder nur Empfänger, Signatur
mit `--sign-passphrase-file`; `--json` (Quelle `"-"`); Sandbox ohne Zielordner bei `--stdout`; abgebrochene
Pipe = Exit 1. Entschlüsseln nur in eine Datei. Tests `tests/cli_stream.rs` (P10).

**Schritt 3 (Füllung, `PAD`) umgesetzt:** `encrypt --pad` (auch mit `--stdin`), Stufe `--privacy high` setzt
`--pad` und `--random-name`. Mit `PAD` wird v4 auch für Datei und Ordner geschrieben; Klartext = Archiv bzw.
Nutzdaten ‖ Nullbytes ‖ Trailer, Füllung = PADMÉ(Länge + 24) − (Länge + 24). Der Leser prüft: nur Nullbytes,
Längen addieren sich, Füllung exakt kanonisch, Archiv endet genau vor der Füllung; bei Strömen wird die
Temporärdatei nach allen Prüfungen auf die Nutzlänge gekürzt. API: `files::EncryptOptions { pad }`,
`encrypt_with_options`, `encrypt_many_with_options` (vorläufig bis #98). Tests: `tests/files_padding.rs`,
`tests/cli_padding.rs`, Unit-Tests; PADMÉ-Referenz `scripts/v4_padme_reference.py` (P06); QA1-FMT-012.

## Umsetzung

Je eigener Plan und PR, Reihenfolge **vor #98** (versionierte Core-API; dort Optionen als
`EncryptOptions`, Strom über `Read`/`Write` im Kern), danach #99 → #71:

1. Kern v4: Header mit Optionsbits, `commit`, Trailer ohne Optionen (Länge), Inhaltstyp 3, Leser für alle
   v4-Regeln, Fuzz-Ziel.
2. CLI Strom (#83): `encrypt --stdin`, `--stdout`, Sandbox ohne Zielordner, Tests P10.
3. Padding (PAD) – Kern + `--pad`.
4. Anonyme Empfänger (ANON) – Kern + `--anonymous-recipients`, CRYPTO.md-Beleg.
5. Verborgener Absender (HIDDEN_SENDER) – Kern + `--hide-sender`.
6. Stufe `--privacy high` vollständig (Menü und Kontextmenü fragen die Stufe seit #315 bereits ab),
   Doku, CHANGELOG.

---

## English

> Draft for #316 (padding, anonymous recipients, hidden sender) **together with #83** (stream mode:
> encrypting from stdin), SPEC v2.21, section 9 U5 and S2. Both change content or header, hence **one**
> version scheme. Draft only; implementation follows in separate PRs. Everything is **optional and off
> by default**: without an option v1/v2/v3 stay **byte for byte** (D3). Random outer names (#315) need
> no new format and are implemented already.

**Goals:** padding (`--pad`) hides the exact size; anonymous recipients (`--anonymous-recipients`)
remove recipient IDs from the plaintext header; hidden sender (`--hide-sender`, only with `--sign-with`)
moves sender key and signature into the encrypted part; stream (`encrypt --stdin`, `--stdout`, #83)
encrypts data of unknown length with constant memory, decrypting only into a file (S2b dropped). Level
`--privacy high` = random name + padding + anonymous recipients + hidden sender where applicable; menu
and context menu offer the level only.

**Decisions P1–P9** (proposals; approved by merging this draft, maintainer's instruction 2026-11-25):
P1 **one** new version **4** with **option bits**, written only when needed (D3), unknown bits →
"unsupported"; P2 new content type **3 "stream"** (raw bytes, no archive), v4 only; P3 lengths, padding
and hidden sender live in a **trailer at the end of the encrypted stream** with a length fixed by the
option bits (reader holds back only that many bytes); P4 **D1 exception: anonymous recipients only on
request, visible IDs (D1) stay the default**; P5 anonymous slots **ML-KEM-1024 only** (equal ciphertext
length); P6 anonymous slots sorted ascending by KEM ciphertext; P7 **PADMÉ** padding over the whole
plaintext length (at most ~12 %, usually < 3 %, leaks O(log log L) bits); P8 key commitment `commit` in
**every** v4 file; P9 the hidden sender signs `SHA3-512(H) ‖ SHA3-512(N) ‖ U64(payload length) ‖ U64(padding length)`
(header, plaintext including padding and the boundary between them – otherwise a recipient could
re-encrypt the trailer and pass padding zeros off as signed content, Codex finding on #324), which together with `commit` fixes the ciphertext.

**Layout:**

```text
M  = "PQKFENC\0" ‖ U16(4) ‖ U8(content 1/2/3) ‖ U32(65536) ‖ nonce_prefix[7] ‖ U16(options)
     ‖ U8(n) ‖ slot_1..n ‖ [sender block, SIGNED only] ‖ commit[32]
H  = M ‖ wrap_1..n (48 bytes each);  file = H ‖ C ‖ [Σ, SIGNED only]
C  = STREAM as v1–v3, stream AAD = SHA3-256(H);  plaintext of C = N ‖ T,  N = payload ‖ padding
options: 0x0001 PAD, 0x0002 ANON, 0x0004 SIGNED (visible, as v3), 0x0008 HIDDEN_SENDER (excludes SIGNED)
anonymous slot = U8(5) ‖ U8(kem = 3) ‖ KEM ciphertext[1568] ‖ nonce[12]
Wanon  = HKDF-SHA3-256(salt = ct, IKM = ss, info = D ‖ "wrap/anonymous\0", 32),  D = "PQKeep/file/v4\0"
commit = SHA3-256(D ‖ "commit\0" ‖ file key)
T = [hidden sender: U8(1) ‖ public key[2592] ‖ Σh[4627]] ‖ U64(payload length) ‖ U64(padding length) ‖ "PQKFEND\0"
Σh = ML-DSA-87.Sign(sk, D ‖ "sig/hidden\0" ‖ SHA3-512(H) ‖ SHA3-512(N) ‖ U64(payload len) ‖ U64(padding len), ctx "PQKeep/pqkf-sig/v1")
padding = zero bytes up to PADMÉ(|payload| + |T|);  PADMÉ(L): E = ⌊log2 L⌋, S = ⌊log2 E⌋ + 1, z = E − S, round up to 2^z
```

Rules: content 3 only in v4; v4 without option bits and with content 1/2 is invalid (D3 stays canonical);
with ANON only type-5 recipient slots (no mixing with type 2), strictly ascending by ciphertext; type 5
without ANON is invalid; the trailer must be complete before the STREAM end flag, lengths must add up
exactly, padding must be zero and exactly PADMÉ (canonical); an archive must end exactly before the
padding.

**Flows:** encrypt → v4 only if needed → header → stream payload (stdin until EOF) → padding → trailer →
last chunk → Σ if SIGNED; with `--stdout` written directly (no temporary file); an interrupted output
stays undecryptable (missing end flag); SIGPIPE is a clean error. Decrypt/`check`: slots with ID as
before (D1 message before decapsulation); with ANON try every type-5 slot (≤ 64 decapsulations; ML-KEM's
implicit rejection yields only randomness for a wrong key), "no slot for this key" only afterwards →
`commit` → stream, holding back |T| bytes → trailer → Σh/Σ → publish. Content 3 is decrypted **only into
a file** (temporary file truncated to the payload length, then published), never to stdout. `inspect`
shows version, options, content type, slots (anonymous ones without ID), an **unverified** visible
sender or just "signed (hidden)"; no length.

**Compatibility:** no new option → v1/v2/v3 unchanged; v4 with all released versions → "unsupported";
unknown bits, SIGNED + HIDDEN_SENDER, type 5 without ANON, type 2 with ANON, kem ≠ 3 → unsupported or
invalid before any derivation; flipping option bits/version/content type → "decryption failed"
(M feeds WrapAAD and stream AAD); truncation (also at a chunk boundary), appending, reordering → "decryption
failed"; broken trailer → invalid; invalid hidden signature or other sender with `--signer` → exit 7;
decrypting a stream without a target or to stdout → usage error.

**Threat model:** padding hides the exact size, not its order of magnitude, the number of files, header
size (number of slots) or timestamps. Anonymous recipients hide *for whom* a file is, not *how many*
slots it has; anonymity relies on ML-KEM's ANO-CCA property (FO transform with implicit rejection; e.g.
Grubbs, Maram, Paterson 2022; Xagawa 2022) – to be re-checked and documented in CRYPTO.md before
implementation. The hidden sender is invisible to outsiders and verifiable by recipients. Streams:
truncation is always detected, decryption never produces partial output.

**Test catalogue (planned):** P01 v1–v3 unchanged byte for byte; P02 round trips for every option and
content combination incl. empty and boundary streams; P03 downgrade attempts; P04 truncation at every
chunk boundary and inside the trailer, appending, reordering; P05 trailer tampering; P06 PADMÉ
reference values from an independent script; P07 anonymous slots at every position 1–64, wrong key,
mixing/level/order rejected; P08 hidden sender tampering incl. a shifted payload/padding boundary (re-encrypted trailer), `--signer`, SIGNED + HIDDEN rejected; P09 wrong
`commit` with several recipients; P10 `--stdin`/`--stdout` large streams, empty input, SIGPIPE, no
temporary file; P11 fuzz target `pqkf_header_v4` and trailer parser (#153), attack catalogue QA1-FMT-*.

**Status: step 1 (core) implemented** (`src/files/format_v4.rs`, `stream_v4.rs`; provisional API until
#98: `files::encrypt_stream`, `files::encrypt_stream_to`; decrypting via `decrypt`/`check`). Refinements:
slots and KEK derivations unchanged from v2, only WrapAAD uses the domain `PQKeep/file/v4\0` (M carries
version and option bits); with `SIGNED` the sender block is byte-identical to v3 and holds the v4 `commit`,
the signature message is v3's; `PAD`, `ANON`, `HIDDEN_SENDER` and unknown bits are "unsupported", v4 only
with content 3; the reader holds the 24 trailer bytes back in the locked buffer; `list` shows no entries
for streams; streams have no original name. Tests: `tests/files_stream_v4.rs`, unit tests, attack case
QA1-FMT-011; the header fuzzer `pqkf_header_v2` also covers v4. **Step 2 (#83, command line)
implemented:** `encrypt --stdin` with `--out` (atomic) or `--stdout` (no temporary file, messages on
stderr); passphrase only via `--passphrase-file` or recipients only, signature with
`--sign-passphrase-file`; `--json` (source `"-"`); no target directory in the sandbox with `--stdout`; a
broken pipe exits with 1; decryption into a file only. Tests `tests/cli_stream.rs` (P10). **Step 3
(padding, `PAD`) implemented:** `encrypt --pad` (also with `--stdin`); level `--privacy high` sets `--pad` and
`--random-name`. With `PAD`, v4 is also written for files and directories; plaintext = archive or payload ‖
zero bytes ‖ trailer, padding = PADMÉ(length + 24) − (length + 24). The reader checks zero bytes only, lengths
adding up, exactly canonical padding and an archive ending exactly before the padding; for streams the
temporary file is truncated to the payload length after all checks. API: `files::EncryptOptions { pad }`,
`encrypt_with_options`, `encrypt_many_with_options` (provisional until #98). Tests, PADMÉ reference
`scripts/v4_padme_reference.py` (P06), QA1-FMT-012.

**Implementation** (one plan and PR each, **before #98**, then #99 → #71): 1. core v4 (option bits,
`commit`, plain trailer, content type 3, reader, fuzz target); 2. CLI stream (#83); 3. padding; 4.
anonymous recipients (with CRYPTO.md evidence); 5. hidden sender; 6. full `--privacy high` (menu and
context menu already ask for the level since #315), docs, changelog.
