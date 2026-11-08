# U0-1: v2-Formatentwurf / v2 format proposal

DE: Nicht implementierter Review-Entwurf zu [U0-1](U0-1.md). Werte sind Vorschläge
für #39, keine bereits ausgelieferten Kennungen. Produktions-v1 bleibt unverändert.
EN: Unimplemented review draft for [U0-1](U0-1.md). Values are #39 proposals,
not shipped identifiers. Production v1 remains unchanged.

## Grundtypen / Primitive encodings

DE: `U8/U16/U32` sind vorzeichenlose Integer, Little Endian. `L(x)` ist
`U32(byte_length(x)) || x`; Text ist UTF-8 ohne NUL-Abschluss außer expliziten
Domänen. `O(x)` ist `00` bei fehlendem optionalem Text, sonst `01 || L(x)`.
JSON-Zahlen müssen ganze nichtnegative Dezimalzahlen ohne Exponent sein; keine
booleschen Ersatzwerte. Doppelte, unbekannte, null- und fehlende Pflichtfelder
ablehnen. Vor Allokation Summen mit Überlaufprüfung und verbleibendem Budget prüfen.
EN: `U8/U16/U32` are unsigned little-endian integers. `L(x)` is
`U32(byte_length(x)) || x`; text is UTF-8 without a NUL except explicit domains.
`O(x)` is `00` for absent optional text, otherwise `01 || L(x)`. JSON numbers are
nonnegative decimal integers without exponents or boolean substitutes. Reject
duplicate, unknown, null and missing required fields. Check summed lengths for
overflow and remaining budget before allocation.

| Wert / Value | Kodierung / Encoding |
|---|---|
| factor | `U8(1)` = `file-32` |
| profile | `U8(1)` file, `U8(2)` file-tpm, `U8(3)` file-fido2 |
| provider | `U16(0)` none, `U16(1)` tpm2-sealed, `U16(2)` ctap2-hmac-secret |
| policy | `U16(0)` file, `U16(1)` hardware proposal |
| wrap role | `U8(1)` normal, `U8(2)` recovery |
| suite | v2 fixes Argon2id 0x13, HKDF-SHA3-256, AES-256-GCM; no negotiation |

DE: Profil/Anbieter/Policy-Kombinationen exakt `(1,0,0)`, `(2,1,1)`, `(3,2,1)`.
Simulator-IDs und andere Kombinationen sind in Produktionscontainern verboten.
EN: Exactly `(1,0,0)`, `(2,1,1)`, `(3,2,1)` profile/provider/policy combinations.
Simulator IDs and other combinations are forbidden in production containers.

## Schutzdescriptor / Protection descriptor

```text
V = U8(factor) || U8(profile) || U16(provider) || U16(policy)
    || L(provider_data)
    || U8(wrap_count) || U8(1) || normal_nonce[12]
    [ || U8(2) || recovery_nonce[12] ]
```

DE: `wrap_count=1` bei file, sonst 2. Reihenfolge normal, recovery; keine frei
wählbaren Listen, weiteren Hüllen oder Rollen. Hüllen-Nonces vor AAD-Erzeugung
ziehen; bei Gleichheit höchstens drei neue Ziehungen, danach oder bei RNG-Fehler
abbrechen. `provider_data` ist leer
bei file. Hardwaredaten werden kanonisch wie unten kodiert, nicht als JSON-Bytes.
EN: `wrap_count=1` for file, otherwise 2. Order normal, recovery; no arbitrary
lists, extra wraps or roles. Generate wrap nonces before building AAD; redraw
duplicates at most three times, then abort, also abort on RNG failure.
`provider_data` is empty for file. Hardware
data uses the canonical encoding below, never JSON text bytes.

| Profil / Profile | `provider_data` (Reihenfolge / order) |
|---|---|
| file | empty |
| file-tpm | `U8(1) || L(primary_template) || L(primary_name) || L(sealed_public) || L(sealed_private)` |
| file-fido2 | `L(rp_id) || L(credential_id) || U8(1) || public_key[65] || Q[32] || U8(1) || U8(1)` |

DE: TPM: U8(1) bezeichnet Owner-Hierarchie. `primary_template` ist TCG-MU-kodiertes
TPM2B_PUBLIC als CreatePrimary-Eingabe; `primary_name` TPM2B_NAME des erzeugten
Parents; `sealed_public/private` TPM2B_PUBLIC/TPM2B_PRIVATE des versiegelten Kindes.
MU-interne Größen bleiben gemäß TCG Big Endian; äußeres L ist Little Endian.
Keine nativen C-Structs, Zeiger, TSS-Kontextdateien oder ungeschützten H-Bytes.
Exaktes Primary-Template, Auth-/Session-Policy und Windows-Nachweis sind Gate P1
in [PROVIDERS](U0-1_PROVIDERS.md); TPM-Schreiben bleibt bis dahin gesperrt.
EN: TPM U8(1) denotes the owner hierarchy. Use TCG MU-encoded TPM2B_PUBLIC input
for CreatePrimary, resulting parent TPM2B_NAME, and the sealed child's
TPM2B_PUBLIC/TPM2B_PRIVATE. Internal MU sizes stay TCG big-endian, outer L is
little-endian. No native C structs, pointers, TSS context files or plaintext H.
Exact primary template, auth/session policy and Windows evidence are gate P1 in
PROVIDERS; TPM writing stays blocked until resolved.

DE: FIDO2: RP-ID-Vorschlag `pqkeep.local`; U8(1) bezeichnet ES256/P-256,
öffentlicher Schlüssel als SEC1 unkomprimiert `04 || x[32] || y[32]` (gültigen
Kurvenpunkt prüfen). Letzte Bytes fordern UP=1, UV=1. `Q` geht unverändert als
einziger 32-Byte-CTAP-hmac-secret-Salt ein. Keine WebAuthn-PRF-Eingabe unter dieser
Kennung: deren Vorhashen ist nicht äquivalent. WebAuthn-Adapter braucht eigene
Kennung oder belegte identische CTAP-Eingabe; kein automatisches Umschalten.
EN: FIDO2 RP ID proposal `pqkeep.local`; U8(1) denotes ES256/P-256, public key
SEC1 uncompressed `04 || x[32] || y[32]` (validate curve point). Last bytes require
UP=1, UV=1. Pass Q unchanged as the single 32-byte CTAP hmac-secret salt. No
WebAuthn PRF input under this ID: its prehash is not equivalent. A WebAuthn adapter
needs a separate ID or proven identical CTAP input; no automatic switching.

## Privater Schlüsselcontainer / Private key container

DE: JSON behält alle v1-Top-Level-Felder und ergänzt das Pflichtobjekt `protection`.
`format_version=2`; `kdf` ergänzt `factor="file-32"`. `cipher` bleibt
`{algorithm,nonce,ciphertext}`, verschlüsselt jetzt den Seed/AES-Schlüssel unter C.
Die gültigen Algorithmusnamen, Metadaten-, Zeit-, Schlüssel-ID-, Public-Key- und
Seed-Längenregeln bleiben wie [FORMAT](FORMAT.md). Optionale Metadaten fehlen
oder enthalten gültigen Text; explizites null ist in v2 verboten.
EN: Keep all v1 top-level JSON fields, add required `protection`.
`format_version=2`; add `factor="file-32"` to `kdf`. Keep
`cipher={algorithm,nonce,ciphertext}`, now encrypting the seed/AES key with C.
Retain FORMAT's algorithm names, metadata/time/key-ID/public-key/seed-length rules.
Optional metadata is absent or valid text; explicit null is forbidden in v2.

| Objekt / Object | exakt erlaubte Felder / exact allowed fields |
|---|---|
| protection, file | `profile`, `normal` |
| protection, hardware | `profile`, `provider`, `policy_version`, `data`, `normal`, `recovery` |
| normal / recovery | `nonce`, `ciphertext` (12/48 decoded bytes) |
| data, TPM | `hierarchy`, `primary_template`, `primary_name`, `sealed_public`, `sealed_private` |
| data, FIDO2 | `rp_id`, `credential_id`, `key_algorithm`, `public_key`, `salt`, `require_up`, `require_uv` |

DE: JSON-Profilnamen stehen in U0-1; Anbieter `tpm2-sealed`/`ctap2-hmac-secret`;
Policy 1; hierarchy `owner`; key_algorithm `ES256`; require_up/uv beide `true`.
Binärfelder sind kanonisches Standard-Base64 mit Padding; key_id bleibt Hex.
Die fehlenden file-Anbieterfelder werden ausschließlich als (0,0,leer) kodiert.
EN: JSON profile names are in U0-1; providers `tpm2-sealed`/`ctap2-hmac-secret`;
policy 1; hierarchy `owner`; key_algorithm `ES256`; require_up/uv both `true`.
Binary fields use canonical padded standard Base64; key_id stays hex. Absent
file provider fields encode only as (0,0,empty).

```text
K = U32(m) || U32(t) || U32(p) || L(S)
Mkey = L("PQKEEP-KEY") || U32(2) || L(algorithm) || key_id[32]
       || L(created_utc) || L(metadata.name)
       || O(organization) || O(company) || O(department) || O(account_type)
       || L(public_key) || L("argon2id") || U32(19) || K
       || L("aes-256-gcm") || payload_nonce[12] || V
```

DE: v2 verwendet neue u32-Präfixe, nicht die v1-u64-Headerfunktion. Keine
Interpretation desselben Headers unter beiden Versionen. Ein Headerfeld wird
genau einmal aus geprüftem JSON in Mkey abgebildet. `cipher.ciphertext` ist
Payload, nicht Teil von Mkey; seine Länge bleibt Seedlänge+16.
EN: v2 uses new u32 prefixes, not the v1 u64 header function. Never interpret the
same header under both versions. Map each validated JSON header field exactly
once into Mkey. `cipher.ciphertext` is payload, excluded from Mkey; length stays
seed length plus 16.

## Datei und Ordner / File and directory

```text
Mfile = "PQKFENC\0"[8] || U16(2) || U8(content) || U8(1)
        || U32(65536) || stream_nonce_prefix[7]
        || U32(m) || U32(t) || U32(p) || U8(len(S)) || S || V
Hfile = Mfile || normal_ciphertext[48] [ || recovery_ciphertext[48] ]
```

DE: content 1=Datei, 2=Ordner; Modus nur 1=Passphrase. Der Salt-Längenwert bleibt
hier das vorhandene u8; alle **neuen variablen** Felder verwenden L. Nach Hfile
beginnt unmittelbar der bestehende STREAM-Archivinhalt. Die Headerlänge ergibt
sich eindeutig aus begrenzten Feldern und Profil, nicht aus einem Scan nach Magic.
EN: Content 1=file, 2=directory; mode only 1=passphrase. Retain the existing u8
salt length here; all **new variable** fields use L. Existing STREAM archive
content starts immediately after Hfile. Bounded fields/profile determine header
length, never scanning for magic.

## AAD und Reihenfolge / AAD and construction order

```text
WrapAAD(role) = D || "aad/wrap\0" || L(M) || U8(role)
Hkey = Mkey || normal_ciphertext[48] [ || recovery_ciphertext[48] ]
KeyPayloadAAD = Dkey || "aad/payload\0" || L(Hkey)
FilePayloadAAD = SHA3-256(Hfile)
```

DE: M ist Mkey oder Mfile. Zuerst alle Nonces/Anbieterdaten, dann M, dann beide
Hüllen, dann H und Payload erstellen. Keine Hüllenchiffrate in WrapAAD, alle
Hüllenchiffrate in PayloadAAD. Damit gibt es keinen AAD-Zyklus. Keine Neusortierung
von Rollen. Auch die unbenutzte Recovery-Hülle ist über PayloadAAD gebunden;
erfolgreiches Unwrap allein ist niemals vollständige Containerprüfung.
EN: M is Mkey or Mfile. Generate all nonces/provider data, then M, both wraps,
H and payload. Exclude wrap ciphertexts from WrapAAD, include all of them in
PayloadAAD; no AAD cycle. Never reorder roles. Even an unused recovery wrap is
bound by PayloadAAD; successful unwrapping alone never authenticates the container.

## Grenzen und Recovery-Text / Bounds and recovery text

DE: Schlüssel-JSON höchstens 65536 UTF-8-Bytes inklusive Whitespace; kanonisches
Hkey zusätzlich ≤65536 Bytes. Binärer Hfile ≤65536 Bytes, Payload davon unabhängig.
Jeder TPM-Blob und Credential-ID 1..16384 dekodierte Bytes; gesamter provider_data
≤65536, begrenzt zusätzlich durch den Gesamtheader. FIDO2-Public-Key exakt 65,
Q exakt 32, RP-ID exakt 12 ASCII-Bytes (`pqkeep.local`). Base64-Längen vor Dekodierung
begrenzen; einzelne Maxima dürfen nicht gemeinsam das Gesamtlimit überschreiten.
EN: Key JSON ≤65536 UTF-8 bytes including whitespace; canonical Hkey also ≤65536.
Binary Hfile ≤65536, independent of payload length. Each TPM blob and credential ID
1..16384 decoded bytes; provider_data ≤65536 and further limited by the overall
header budget. FIDO2 public key exactly 65, Q 32, RP ID exactly 12 ASCII bytes
(`pqkeep.local`). Bound Base64 length before decoding; individual maxima may not
jointly exceed the overall limit.

```text
recovery export = ASCII("PQKEEP-RECOVERY-1:") || Base64(R[32]) || LF
```

DE: Exakt 63 Bytes, kanonisches Padding, genau ein LF; kein CRLF/BOM/Whitespace,
keine mehreren Datensätze. Höchstens 64 Bytes lesen, danach Längenprüfung. Kennung
versioniert das Exportformat, nicht den Container. R wird nicht aus P/F abgeleitet.
EN: Exactly 63 bytes, canonical padding, one LF; no CRLF/BOM/whitespace or multiple
records. Read at most 64 bytes, then check length. The marker versions the export,
not the container. R is not derived from P/F.
