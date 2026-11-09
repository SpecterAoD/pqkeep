# Passphrase-Regeln / Passphrase rules

**DE** | [EN](#english)

## Normalisierung

Jede Passphrase wird vor allem anderen mit **Unicode NFKC** normalisiert. Dadurch ergeben gleich
aussehende Eingaben unter Windows, Linux und verschiedenen Tastaturen dieselben Bytes (z. B. „é“ als
ein Zeichen oder als „e“ + Akzent, Vollbreite „Ａ“ → „A“, Ligatur „ﬁ“ → „fi“). Gezählt werden
**Unicode-Zeichen nach NFKC**, nicht Bytes („ä“ zählt 1). Ein zusammengesetztes Emoji
(z. B. Familie) zählt mehrfach.

## Pflichtregeln (Ablehnung mit Begründung)

| Regel | Grund |
|---|---|
| mindestens 16, höchstens 1024 Zeichen | `TooShort` / `TooLong` |
| Kleinbuchstabe, Großbuchstabe, Ziffer, Sonderzeichen | `Missing…` |
| keine Steuerzeichen | `ControlCharacter` |
| keine Wiederholung ≥ 4 („aaaa“, auch „AaAa“) | `Repetition` |
| keine Folge ≥ 4 („1234“, „abcd“, „dcba“) | `Sequence` |
| keine Tastaturreihe ≥ 4 (QWERTZ/QWERTY, auch rückwärts) | `KeyboardPattern` |
| häufige Passwörter/Wörter machen nicht ≥ ⅓ aus (auch Leetspeak „P@ssw0rt“) | `Blocklisted` |
| geschätzte Entropie ≥ 128 Bit (mit `--min-bits` bis 256) | `LowEntropy` |

Alle zutreffenden Gründe werden **gleichzeitig** gemeldet, jeweils auf Deutsch und Englisch.
Umlaute (ä, ö, ü, ß) zählen als Buchstaben, Leer- und Satzzeichen als Sonderzeichen.

**Blocklist-Schwelle:** Wörter aus der Liste mindern immer die geschätzte Entropie. Abgelehnt wird
erst, wenn sie mindestens ein Drittel der Passphrase ausmachen. Sonst würden normale Sätze wie
„Mein Test: 7 Kühe, 3 Pferde & Hund!“ abgelehnt. Die Liste ist klein und selbst erstellt (DE/EN);
sie ersetzt keine Prüfung gegen große Passwortlisten.

## Warum 128 Bit? (Post-Quanten)

Gegen das Raten einer Passphrase hilft ein Quantencomputer nur über den Grover-Algorithmus: Er halbiert
die Bits **höchstens** (80 → rechnerisch 40, 128 → 64). Praktisch müsste jeder Rateversuch Argon2id mit
≥ 64 MiB auf dem Quantencomputer selbst ausführen, nacheinander – nach heutigem Wissen unrealistisch.
Weil die Passphrase aber das schwächste Glied gegenüber AES-256/ML-KEM ist und Schätzungen bei selbst
ausgedachten Passphrasen eher zu hoch liegen, gilt seit SPEC v2.9 **≥ 128 Bit**: Selbst ohne den Schutz
durch Argon2 bleiben so rechnerisch ≥ 64 Bit. 128 Bit entsprechen etwa 20 zufälligen Zeichen oder etwa
10 zufälligen Wörtern. Bestehende Dateien bleiben lesbar; geprüft wird nur beim Erstellen.

## Entropieschätzung (Wort-Modell)

Angreifer raten Wörter und Muster, nicht einzelne Buchstaben. Deshalb:

| Teil | Wert |
|---|---|
| einzelnes zufälliges Zeichen | log2(Zeichenvorrat), Vorrat = Summe der vorkommenden Klassen (26/26/10/33, Nicht-ASCII 100) |
| Buchstabenfolge | höchstens wie Wörter: Wort aus den Listen ≈ 12,9 Bit (+1 bei Großbuchstaben), unbekanntes Wort 18 Bit je angefangene 10 Buchstaben |
| Ziffer | log2(10) ≈ 3,3 Bit (Jahreszahlen, PINs) |
| wiederholtes Sonder-/Trennzeichen | 1 Bit |
| erkannte Muster (Wiederholung, Folge, Tastatur, Blocklist) | 0 Bit |

**Wortlisten** (`data/wordlists/`, rund 38 500 Wörter): EFF (Englisch, CC BY 4.0 – freigegebene
Ausnahme), BIP-39 (10 Sprachen, MIT), dys2p (Deutsch, nach EFF-Regeln, BSD-3), Björn Albers
(Deutsch, MIT). Zusammengesetzte deutsche Wörter, die in keiner Liste stehen, fängt das Modell
„unbekanntes Wort“ ab.

Beispiele: „FIPS-140-validiert“ ≈ 53 Bit, „Hund-Katze-Maus-2024!“ ≈ 70 Bit → abgelehnt mit dem Grund
„besteht überwiegend aus Wörtern“. „Kaffee Tasse Wolke Garten Fenster Brot 7!“ ≈ 105 Bit → angenommen.
Faustregel: etwa 6 Wörter oder zufällige Zeichen.

**Grenze:** Das bleibt eine Heuristik. Bekannte Zitate, Liedzeilen oder persönliche Daten (Namen,
Geburtstage) kann sie nicht erkennen. Die sicherste Wahl ist der eingebaute Generator.

## Generator

- Zufall aus dem Betriebssystem, **Rejection Sampling** ohne Modulo-Bias (intern für alle
  Alphabetgrößen vollständig geprüft).
- Alphabet: 94 druckbare ASCII-Zeichen; optional ohne verwechselbare Zeichen `0 O 1 l I | \` ' "` (85).
- Standard 32 Zeichen ≈ 210 Bit (ohne verwechselbare ≈ 205 Bit), Länge 24–256 (`pqkeep passphrase 40`
  oder `--length 40`). Einstufung in der Ausgabe: gut ≥ 128 Bit, sehr stark ≥ 192 Bit.
- Erfüllt ein Kandidat nicht alle Regeln, wird er vollständig verworfen und neu gezogen
  (gleichmäßige Verteilung über alle gültigen Passphrasen). Die angezeigte Entropie nach Formel
  `log2(Alphabet) × Länge` ist dadurch minimal zu hoch (Größenordnung unter 1 Bit).
- Wortlisten-Variante (Diceware): späteres Update mit eigener bzw. gemeinfreier Liste.

## Schutz im Code

- `Passphrase`: normalisiert, liegt in `SecretBytes` (Nullen beim Freigeben), kein `Debug`/`Clone`.
- `StrongPassphrase`: nur über die Prüfung erzeugbar. **Nur damit** kann ein Schlüssel geschützt
  werden (`protect`). Zum Öffnen reicht eine normalisierte `Passphrase` (`unprotect`), damit
  vorhandene Daten auch bei geänderten Regeln lesbar bleiben.
- Eingabe nie über Kommandozeilenargumente oder Umgebungsvariablen (umgesetzt in der CLI, Schritt 4).

---

## English

**Normalisation:** every passphrase is normalised with **Unicode NFKC** first, so equal-looking input
yields the same bytes on every platform. Length counts **Unicode characters after NFKC**, not bytes.

**Mandatory rules** (all applicable reasons reported at once, in German and English): 16–1024
characters; lowercase, uppercase, digit, special character (space and punctuation count as special,
umlauts as letters); no control characters; no repetition ≥ 4, sequence ≥ 4 or keyboard row ≥ 4
(QWERTZ/QWERTY, also reversed); common passwords/words (also leetspeak) must not make up ≥ ⅓;
estimated entropy ≥ 128 bits (up to 256 with `--min-bits`; why 128: Grover at most halves the bits and
each guess would need Argon2id on the quantum computer – even without that, 128 leaves ≥ 64 bits). Blocklisted words always reduce the estimate but only cause rejection
from one third upwards, so that ordinary sentences are not rejected for containing e.g. "test".

**Entropy estimate (word model):** single random characters count log2(pool); a letter run counts at most
like words (listed word ≈ 12.9 bits, +1 for capitals; unknown word 18 bits per started 10 letters);
digits log2(10); a repeated special/separator 1 bit; detected patterns 0. Bundled word lists (≈ 38,500
words): EFF (CC BY 4.0, approved exception), BIP-39 (10 languages, MIT), dys2p (German, BSD-3), Björn
Albers (German, MIT). "FIPS-140-validiert" ≈ 53 bits and "Hund-Katze-Maus-2024!" ≈ 70 bits are rejected
("consists mostly of words"); a 6-word sentence passes. Still a heuristic: quotes, lyrics or personal data
are not recognised; the built-in generator is the safest choice.

**Generator:** OS randomness, rejection sampling without modulo bias, 94 printable ASCII characters
(85 without ambiguous ones), default 32 characters ≈ 210 bits, length 24–256 (`pqkeep passphrase 40`); rating good ≥ 128, very strong ≥ 192 bits. Candidates failing any
rule are discarded entirely; the displayed formula value is therefore marginally too high (well below
1 bit). Diceware with a self-made or public-domain word list is planned as a later update.

**In code:** `Passphrase` (normalised, zeroised, no `Debug`/`Clone`); `StrongPassphrase` only via the
check and required by `protect`; `unprotect` accepts any normalised `Passphrase`.
