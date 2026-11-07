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
| geschätzte Entropie ≥ 80 Bit | `LowEntropy` |

Alle zutreffenden Gründe werden **gleichzeitig** gemeldet, jeweils auf Deutsch und Englisch.
Umlaute (ä, ö, ü, ß) zählen als Buchstaben, Leer- und Satzzeichen als Sonderzeichen.

**Blocklist-Schwelle:** Wörter aus der Liste mindern immer die geschätzte Entropie. Abgelehnt wird
erst, wenn sie mindestens ein Drittel der Passphrase ausmachen. Sonst würden normale Sätze wie
„Mein Test: 7 Kühe, 3 Pferde & Hund!“ abgelehnt. Die Liste ist klein und selbst erstellt (DE/EN);
sie ersetzt keine Prüfung gegen große Passwortlisten.

## Entropieschätzung

`log2(Zeichenvorrat) × effektive Länge`. Zeichenvorrat = Summe der vorkommenden Klassen
(Kleinbuchstaben 26, Großbuchstaben 26, Ziffern 10, ASCII-Sonderzeichen inkl. Leerzeichen 33,
Nicht-ASCII pauschal 100). Zeichen, die zu einem erkannten Muster gehören, zählen nicht zur Länge.

**Grenze:** Das ist eine Heuristik. Sie bewertet die Form, nicht wie die Passphrase gewählt wurde.
Eine bekannte Zeile aus einem Lied kann die Regeln erfüllen und trotzdem leicht zu erraten sein.
Die sicherste Wahl ist der eingebaute Generator.
Beispiel aus den Tests: Das Fachwort „FIPS-140-validiert“ erfüllt alle Regeln (18 Zeichen, alle
Klassen, keine Muster), wäre aber leicht zu erraten. Eine größere Wörterbuchprüfung ist eine mögliche
spätere Verbesserung.

## Generator

- Zufall aus dem Betriebssystem, **Rejection Sampling** ohne Modulo-Bias (intern für alle
  Alphabetgrößen vollständig geprüft).
- Alphabet: 94 druckbare ASCII-Zeichen; optional ohne verwechselbare Zeichen `0 O 1 l I | \` ' "` (85).
- Standard 24 Zeichen ≈ 157 Bit (ohne verwechselbare ≈ 154 Bit), Länge 16–256.
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
estimated entropy ≥ 80 bits. Blocklisted words always reduce the estimate but only cause rejection
from one third upwards, so that ordinary sentences are not rejected for containing e.g. "test".

**Entropy estimate:** `log2(pool) × effective length`; pool = sum of classes present (26/26/10/33,
non-ASCII 100); characters in detected patterns do not count. It is a heuristic that judges shape,
not how the passphrase was chosen; the built-in generator is the safest choice. Example from the tests:
the technical term "FIPS-140-validiert" meets every rule yet would be easy to guess; a larger dictionary
check is a possible later improvement.

**Generator:** OS randomness, rejection sampling without modulo bias, 94 printable ASCII characters
(85 without ambiguous ones), default 24 characters ≈ 157 bits, length 16–256. Candidates failing any
rule are discarded entirely; the displayed formula value is therefore marginally too high (well below
1 bit). Diceware with a self-made or public-domain word list is planned as a later update.

**In code:** `Passphrase` (normalised, zeroised, no `Debug`/`Clone`); `StrongPassphrase` only via the
check and required by `protect`; `unprotect` accepts any normalised `Passphrase`.
