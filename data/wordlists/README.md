# Wortlisten / Word lists

DE: Diese Listen dienen der **Stärkeprüfung** von Passphrasen (`src/security/dictionary.rs`):
Wörter aus diesen Listen zählen bei der Entropieschätzung nur wie ein Listenwort (≈ 12,9 Bit),
nicht wie zufällige Buchstaben. Sie sind Datendateien, kein Programmcode.

EN: These lists are used for passphrase **strength checking** (`src/security/dictionary.rs`):
words from these lists only count like one list word (≈ 12.9 bits) in the entropy estimate,
not like random letters. They are data files, not program code.

**Bearbeitung / Processing:** Würfelnummern entfernt, Unicode NFKC, Kleinschreibung, ein Wort
pro Zeile. Sonst unverändert. / Dice numbers removed, Unicode NFKC, lowercase, one word per line.
Otherwise unchanged.

| Datei / File | Quelle / Source | Stand / Version | Lizenz / Licence |
|---|---|---|---|
| `eff_large.txt`, `eff_short_1.txt`, `eff_short_2.txt` | Electronic Frontier Foundation, https://www.eff.org/dice (Dateien vom 18.07.2016 / 08.09.2016) | heruntergeladen / downloaded 2026-11-07 | **CC BY 4.0** (EFF-Copyright-Richtlinie) – Ausnahme von SPEC 5c, siehe dort |
| `bip39_*.txt` (10 Sprachen / languages) | BIP-39, https://github.com/bitcoin/bips/tree/master/bip-0039 | Commit `f9cff97a6baa76ad213fbc4acfb286e016efdbef` | **MIT** (BIP-39-Kopf: „License: MIT“) |
| `dys2p_de_7776.txt`, `dys2p_de_2048.txt`, `dys2p_de_1626.txt`, `dys2p_de_1296.txt` | dys2p, https://github.com/dys2p/wordlists-de (nach den Regeln der EFF-Listen) | Commit `6ef31b9aefb8735a7b066592393d12843ec502cd` | **BSD-3-Clause** (gewählt aus Unlicense / CC0 / BSD-3) |
| `bjoernalbers_german.txt` | Björn Albers, https://github.com/bjoernalbers/diceware-wordlist-german | Commit `9e48d27be3b9b5c7c2c967f2bb7e6d0b73cdc12c` | **MIT** |

Bewusst **nicht** aufgenommen / deliberately **not** included: `klamann/diceware-dereko`
(abgeleitet von DeReKo unter CC BY-NC 3.0 – „nicht kommerziell“ ist mit Open Source unvereinbar /
derived from DeReKo under CC BY-NC 3.0 – "non-commercial" is incompatible with open source).

Lizenztexte / licence texts: [`LICENSES.md`](LICENSES.md).
