# Base64 private remainder / Privater Base64-Restblock

DE: Abschließender R6-Providerabgleich, vor Produktionsänderungen signieren.
Konkreter Befund: base64ct1.8.3 Encoding::encode erzeugt bei ungepaddeter Ausgabe
private tmp_in[3]/tmp_out[4]. API-Token mit32Zufallsbytes erreichen diesen Pfad,
obwohl Quelle und Ziel bereits SecretBytes sind. Nicht als Registergrenze behandeln.
EN: Existing locked caller buffers do not protect these provider remainder arrays.

DE: Exakt vorhandenes base64ct1.8.3-Archiv gegen Cargo.lock prüfen; alle Produktions-
module/Lizenzen und Herkunfts-/Patchregister erhalten. Additiver geliehener Encoder
mit festem öffentlichem Anfangs-Scratch; denselben konstanten Alphabet-/3-Byte-Kern,
Längenvertrag und Paddinglogik wiederverwenden. Keine neue Kodierung und kein Unsafe.
EN: Root token creation prelocks the entire remainder workspace before private input.
Zeroize/Drop and host wiping precede unlock/free; lock failure has no fallback.
Ordinary Base64 encode/decode APIs and all versions remain compatible.

DE: Dateien: API-Token-Einstieg und eigene Tests, eng begrenzter versionierter
Provider/Manifest-/Lockfile-/Herkunftsabgleich, Sicherheitsnachweise. Öffentliche
Schlüssel/Signaturen/Salts/Nonces/Chiffrate und statische PowerShell-Skripte getrennt
klassifizieren. Die vorhandenen Unicode-Char-Primitiven samt tatsächlichen Aufrufern
prüfen; kein pauschaler Schutz der gewöhnlichen NFC-Iteratoren behaupten.
EN: Require all Base64 remainder classes, independent Python base64 references,
both alphabets/padding modes, sentinels/invalid geometry, stable actual locked
scratch, error/unwind/resource denial and existing token/public-envelope tests.
Preserve features, native Linux/Windows/ARM64, source/history scans and all CI gates.
Complete Argon2 and all remaining R6 matrix/rollback proofs before merge/closure.
