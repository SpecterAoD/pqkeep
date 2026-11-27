# Format v3: Absender-Signatur in `.pqkf` / Format v3: sender signature inside `.pqkf`

**DE** | [EN](#english)

> Umsetzung von #44 (SPEC Abschnitt 9, U1 – „Erweiterung für `.pqkf`“), SPEC v2.18. Eine `.pqkf`
> beweist bisher, dass der Inhalt unverändert ist, aber nicht, **wer** verschlüsselt hat: Im
> Empfänger-Modus kann jeder mit dem öffentlichen Schlüssel gültige Dateien erzeugen. Format v3
> bettet optional eine ML-DSA-87-Signatur des Absenders in den Container ein. Unsignierte Dateien
> bleiben v1 bzw. v2, **Byte für Byte wie bisher**.

## Entscheidungen

| Nr. | Frage | Entscheidung | Verworfene Alternative |
|---|---|---|---|
| S1 | Wo steht die Signatur? | **am Dateiende** (feste Länge 4627 Byte); der Absender-Schlüssel steht im Header | Signatur im Header: dann zwei Durchläufe oder Zurückspringen in der Datei nötig |
| S2 | Was wird signiert? | **ganzer Header** (alle Zugänge, alle Hüllen, Absender-Schlüssel) **und der ganze verschlüsselte Inhalt** | nur der Klartext: Prüfen nur nach dem Entschlüsseln möglich, Empfängerliste nicht gebunden |
| S3 | Schutz gegen Entfernen der Signatur | Version **3** und Absender-Schlüssel stehen im Header; der Header geht über die Strom-AAD in **jeden** Block ein | Kennzeichen nur am Ende: ließe sich abschneiden |
| S4 | Gleicher Inhalt für alle Empfänger | **Schlüsselbindung** `commit = SHA3-256(Domäne ‖ Dateischlüssel)` im Header, nach dem Auspacken geprüft | ohne: ein böswilliger Absender könnte Empfängern verschiedene Dateischlüssel und damit verschiedene Klartexte unterschieben (AES-GCM bindet den Schlüssel nicht) |
| S5 | Öffentlicher Schlüssel des Absenders | **vollständig im Header** (2592 Byte): Prüfen ohne zusätzliche Datei; angezeigt werden Schlüssel-ID und Fingerabdruck | nur Schlüssel-ID: Prüfen bräuchte immer `*.pub.json` |
| S6 | Ungültige Signatur | **Fehler, keine Ausgabe** (wie Manipulation) | nur Warnung |
| S7 | Wann wird v3 geschrieben? | **nur mit `--sign-with`**; sonst unverändert v1/v2 (D3) | immer v3 |
| S8 | Algorithmus | nur **ML-DSA-87** (Kennung 1), Kontext `PQKeep/pqkf-sig/v1`, „hedged“ wie `.pqsig` | ML-DSA-44/65 oder hybride Signaturen (später über #275) |

## Aufbau

```text
M  = "PQKFENC\0" ‖ U16(3) ‖ U8(inhalt 1/2) ‖ U32(65536) ‖ nonce_prefix[7] ‖ U8(n) ‖ zugang_1..n
     ‖ U8(algorithmus = 1) ‖ öffentlicher_schlüssel[2592] ‖ commit[32]
H  = M ‖ hülle_1..n (je 48 Byte)
Datei = H ‖ C ‖ Σ
C  = STREAM-Chiffrat wie v1/v2 (Blöcke à 64 KiB + Tag, Endmarke im letzten Block)
Σ  = ML-DSA-87-Signatur (genau 4627 Byte), danach Dateiende

Zugänge, Hüllen, WrapAAD(i) und Ableitungen: unverändert wie v2 (V2_DRAFT.md); M enthält jetzt
Version 3 und den Absenderblock, damit ändern sich alle WrapAAD.
Strom-AAD = SHA3-256(H)
commit    = SHA3-256("PQKeep/file/v3\0commit\0" ‖ Dateischlüssel)
Nachricht = "PQKeep/file/v3\0sig\0" ‖ SHA3-512(H) ‖ SHA3-512(C) ‖ U64(Länge C)
Σ         = ML-DSA-87.Sign(geheimer Schlüssel, Nachricht, Kontext "PQKeep/pqkf-sig/v1")
Schlüssel-ID = SHA3-256(öffentlicher_schlüssel)   (wie bei *.pub.json und .pqsig)
```

Regeln: alle Regeln von v2 für Zugänge (1–65, Passphrase höchstens einmal und zuerst, Empfänger
streng aufsteigend); Algorithmus ≠ 1 → „nicht unterstützt“; Header ≤ 256 KiB. Die Länge von C ergibt
sich aus Dateigröße − Länge von H − 4627; ist die Datei kürzer, ist sie ungültig.

## Ablauf

**Verschlüsseln:** Absender-Schlüssel (ML-DSA-87, `*.key.json`) entsperren → neuer Dateischlüssel →
`commit` → Header mit Absenderblock → Strom schreiben und dabei SHA3-512(C) bilden → signieren, sofort
gegenprüfen → Σ anhängen → atomar veröffentlichen (wie bisher, nie überschreiben).

**Entschlüsseln und `check`:** Header lesen → Dateischlüssel wie v2 auspacken → `commit` prüfen
(Vergleich ohne frühen Abbruch; Abweichung = „Entschlüsselung fehlgeschlagen“) → C genau bis zur
berechneten Länge lesen, entschlüsseln und hashen → Σ lesen, Dateiende prüfen → Signatur prüfen →
erst dann wird die Ausgabe veröffentlicht. Ergebnis: Schlüssel-ID des Absenders.

**Ohne Terminal:** Bekommt die Datei selbst eine Passphrase, braucht der Signaturschlüssel eine eigene
Quelle: `--sign-passphrase-file <datei>` (Regeln wie `--passphrase-file`, #286). Ohne diese Option ist
das ein Bedienfehler; für Empfänger (`--to`) genügt die übliche Passphrase-Quelle.

**`inspect`:** zeigt, dass die Datei signiert ist, und Schlüssel-ID/Fingerabdruck des Absenders –
ausdrücklich **ungeprüft** (es wird kein Inhalt gelesen). Geprüft wird mit `check` oder beim
Entschlüsseln.

## Kompatibilität und Fehler

| Fall | Ergebnis |
|---|---|
| unsignierte Datei (v1/v2) | unverändert, Byte für Byte |
| v3-Datei mit 0.1.0-beta.1 bis -beta.3 | „nicht unterstützt“ (unbekannte Version) – nie still ohne Prüfung |
| Signatur entfernt oder abgeschnitten | Strom endet an falscher Stelle → „Entschlüsselung fehlgeschlagen“, keine Ausgabe |
| Signatur verändert, anderer Absender eingetragen, Inhalt oder Header verändert | Fehler, keine Ausgabe |
| angehängte Daten nach Σ | Fehler, keine Ausgabe |
| v3 zu v2 umgeschrieben (Absenderblock entfernt) | Header und damit Strom-AAD ändern sich → „Entschlüsselung fehlgeschlagen“ |
| `commit` passt nicht zum Dateischlüssel | „Entschlüsselung fehlgeschlagen“ |
| `--signer <pub.json>` angegeben, Datei unsigniert oder anderer Absender | Fehler (Exit-Code 7), keine Ausgabe |
| Absender-Schlüssel ist kein ML-DSA-87 | „nicht unterstützt“ |

## Was die Signatur beweist – und was nicht

- **Beweist:** Der Inhaber des privaten Schlüssels mit der angezeigten Schlüssel-ID hat genau diese
  Datei – mit genau diesen Empfängern – erstellt; seitdem wurde nichts verändert. Weiterleiten an
  andere Empfänger unter seinem Namen ist nicht möglich (die Empfängerliste ist signiert).
- **Beweist nicht, wer dieser Inhaber ist:** Fingerabdruck auf einem zweiten Weg bestätigen oder
  beim Entschlüsseln `--signer <absender.pub.json>` verlangen.
- Ein Empfänger kann den Inhalt entschlüsseln und **unter eigenem Namen** neu verschlüsseln; das ist
  bei jeder Verschlüsselung so und kein Fehler des Formats.
- Keine qualifizierte elektronische Signatur nach eIDAS; kein vertrauenswürdiger Zeitstempel.
- Die sichtbare Absender-ID verrät (wie die Empfänger-IDs, D1), von wem eine Datei stammt.

## Abgrenzung

- `.pqsig` (abgesetzte Signatur beliebiger Dateien) bleibt unverändert bestehen.
- Stream-Modus (#83) und Privatsphäre-Optionen (#316): gemeinsamer Formatentwurf v4 ([V4_DRAFT.md](V4_DRAFT.md)), der diesen Absenderblock übernimmt. Der verborgene Absender (v4, `HIDDEN_SENDER`) nutzt denselben Schlüssel und Kontext, signiert aber Header, Klartext-Hash und Längen im Trailer statt des Chiffrats.
- Ob man einem Absender vertraut, entscheidet später das Kontaktverzeichnis (#105/#107).
- Krypto-Richtlinie und Suite-Migration (#275/#276): die Algorithmus-Kennung im Absenderblock ist
  dafür vorgesehen; weitere Algorithmen nur mit eigener Formatänderung.
- Menü und Kontextmenü (#287): optionale Frage „Als Absender signieren?“ beim Verschlüsseln; nach dem
  Entschlüsseln nennen Terminal und Fertig-Fenster den geprüften Absender. Mit Passphrase-Schutz
  schreiben beide Passwortfenster nacheinander in dieselbe Pipe zum Kindprozess – der
  Kontextmenü-Prozess sieht keine Passphrase.
- Die REST-API bietet die Signatur nicht an (dort bewusst keine Dateiverschlüsselung).

---

## English

> Implements #44 (SPEC section 9, U1 – "extension for `.pqkf`"), SPEC v2.18. Until now a `.pqkf`
> proves that its content is unchanged, but not **who** encrypted it: in recipient mode anyone with the
> public key can create valid files. Format v3 optionally embeds the sender's ML-DSA-87 signature in the
> container. Unsigned files stay v1 or v2, **byte for byte as before**.

**Decisions:** S1 the signature is at the **end of the file** (fixed 4627 bytes), the sender's key in the
header (a signature in the header would need two passes or seeking back); S2 the **whole header** (all
slots, wraps, sender key) **and the whole ciphertext** are signed (plaintext only would need decryption to
verify and would not bind the recipient list); S3 version **3** and the sender key are in the header,
which enters **every** chunk through the stream AAD, so the signature cannot be stripped; S4 a **key
commitment** `commit = SHA3-256(domain ‖ file key)` in the header, checked after unwrapping, so a
malicious sender cannot give recipients different file keys and thus different plaintexts (AES-GCM is
not key-committing); S5 the sender's **full public key** (2592 bytes) is in the header, so verifying needs
no extra file; key ID and fingerprint are shown; S6 an invalid signature is an **error, no output**; S7 v3
is written **only with `--sign-with`**, otherwise v1/v2 unchanged (D3); S8 **ML-DSA-87** only (ID 1),
context `PQKeep/pqkf-sig/v1`, hedged as for `.pqsig`.

**Layout:** see the code block above – `M` as in v2 with version 3 plus the sender block (algorithm,
public key, commitment); file = `H ‖ C ‖ Σ`; slots, wraps, wrap AAD and derivations unchanged from v2
(`M` now differs, so every wrap AAD differs); stream AAD = SHA3-256(H); message =
`"PQKeep/file/v3\0sig\0" ‖ SHA3-512(H) ‖ SHA3-512(C) ‖ U64(len C)`; key ID = SHA3-256(public key). All v2
slot rules apply; algorithm ≠ 1 is unsupported; header ≤ 256 KiB; the length of C is file size − len(H) −
4627.

**Flow:** encrypting – unlock the sender key, new file key, commitment, header with sender block, stream
while hashing C, sign and cross-check, append Σ, publish atomically. Decrypting and `check` – read the
header, unwrap as in v2, check the commitment (no early exit), read C exactly up to the computed length
while decrypting and hashing, read Σ and require end of file, verify; only then is the output published.
`inspect` shows that the file is signed and the sender's key ID/fingerprint, explicitly **unverified**.
Without a terminal, a file that gets its own passphrase needs a separate source for the signing key:
`--sign-passphrase-file <file>` (rules as `--passphrase-file`, #286); otherwise this is a usage error.

**Compatibility:** see the table above – unsigned files unchanged; v3 files are "unsupported" in
0.1.0-beta.1 to -beta.3 (never silently unverified); stripped, truncated, altered or appended data,
another sender, rewriting v3 to v2 or a wrong commitment all fail without output; `--signer` with an
unsigned file or another sender fails (exit code 7); a non-ML-DSA-87 sender key is unsupported.

**What the signature proves:** the holder of the private key with the shown key ID created exactly this
file for exactly these recipients and nothing changed since; forwarding to other recipients under the
sender's name is impossible (the recipient list is signed). It does **not** prove who that holder is
(confirm the fingerprint or require `--signer`). A recipient can decrypt and re-encrypt under their own
name (inherent to any encryption). Not an eIDAS signature, no trusted timestamp. The visible sender ID
reveals who a file comes from.

**Scope:** `.pqsig` stays; stream mode (#83) and the privacy options (#316) share format draft v4 ([V4_DRAFT.md](V4_DRAFT.md)), which reuses the sender block (the hidden sender, v4 `HIDDEN_SENDER`, uses the same key and context but signs header, plaintext hash and lengths in the trailer instead of the ciphertext); trust decisions belong to the
contacts directory (#105/#107); the algorithm ID is ready for the crypto policy (#275/#276); not offered
via the REST API (it deliberately offers no file encryption). Menu and context menu (#287) ask
"Sign as sender?" when encrypting and name the verified sender after decrypting; with passphrase
protection both password windows write into the same pipe to the child – the context menu process
never sees a passphrase.
