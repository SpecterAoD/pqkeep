# Schlüsselverwaltung / Key management

**DE** | [EN](#english)

## Sicherung

- **Schlüsseldatei** (`*.key.json`) und **Passphrase** sind beide nötig. Ohne Passphrase ist die
  Schlüsseldatei wertlos – es gibt **keine Wiederherstellung** und keine Hintertür.
- Schlüsseldatei an mindestens zwei getrennten Orten sichern (z. B. verschlüsselter USB-Stick an
  einem anderen Ort, Backup-Medium). Die Datei ist mit AES-256-GCM verschlüsselt; die **Metadaten**
  (Name, Organisation …) stehen aber im Klartext darin.
- Die Passphrase getrennt von der Datei aufbewahren, z. B. im Passwortmanager oder auf Papier an
  einem sicheren Ort – nie neben der Schlüsseldatei.
- Öffentliche Schlüssel (`*.pub.json`) sind nicht geheim; sie lassen sich jederzeit mit
  `pqkeep export` aus der Schlüsseldatei neu erzeugen.
- Verschlüsselte Dateien (`.pqkf`) im Empfänger-Modus lassen sich **nur** mit der passenden
  Schlüsseldatei öffnen – ohne Sicherung des Schlüssels sind sie verloren.

## Passphrase ändern

Eine eigene Funktion gibt es noch nicht. Vorgehen: neuen Schlüssel erzeugen (siehe Rotation) oder
abwarten – ein Befehl zum Neu-Verschlüsseln der Schlüsseldatei ist als Update denkbar.

## Rotation und Ablauf

- Schlüssel tragen ein Erstellungsdatum (`created_utc`), aber kein Ablaufdatum. Empfehlung:
  Verschlüsselungsschlüssel (ML-KEM) etwa alle 1–2 Jahre oder sofort bei Verdacht auf
  Kompromittierung ersetzen.
- Ablauf einer Rotation: neuen Schlüssel erzeugen, neuen öffentlichen Schlüssel weitergeben (mit
  Fingerabdruck über einen zweiten Kanal bestätigen lassen), alte Daten mit dem alten Schlüssel
  entschlüsseln und mit dem neuen erneut verschlüsseln, alten Schlüssel erst danach außer Betrieb
  nehmen.
- Wird ein Schlüssel kompromittiert, sind alle damit verschlüsselten Dateien betroffen – auch alte
  Kopien. Rotation schützt nur künftige Daten.

## Löschen

Sicheres Löschen ist auf SSDs und modernen Dateisystemen **unzuverlässig** (Wear Leveling, Kopien,
Snapshots). Schutzprinzip ist daher Verschlüsselung statt Löschen: unverschlüsselte Originale gar
nicht erst dauerhaft speichern, Datenträger mit Vollverschlüsselung betreiben. PQKeep löscht
Originale nach dem Verschlüsseln bewusst nicht.

## Fingerabdrücke prüfen

Bevor man für jemanden verschlüsselt, den Fingerabdruck seines öffentlichen Schlüssels
(`pqkeep inspect anna.pub.json`) über einen zweiten Kanal bestätigen (Telefon, persönlich).
Sonst kann ein untergeschobener Schlüssel unbemerkt bleiben.

---

## English

**Backup:** both the key file (`*.key.json`) and the passphrase are required – there is **no
recovery** and no backdoor. Keep the key file in at least two separate places; the file is encrypted
with AES-256-GCM, but its **metadata** is plaintext. Store the passphrase separately from the file
(password manager or paper in a safe place). Public keys are not secret and can be re-created with
`pqkeep export`. Recipient-mode `.pqkf` files can **only** be opened with the matching key file.

**Changing the passphrase:** no dedicated command yet; create a new key (see rotation).

**Rotation and expiry:** keys carry a creation date but no expiry. Replace encryption keys (ML-KEM)
roughly every 1–2 years or immediately on suspected compromise: create a new key, share the new
public key (confirm the fingerprint over a second channel), re-encrypt data, retire the old key last.
A compromised key affects all files encrypted with it, including old copies.

**Deletion:** secure deletion is **unreliable** on SSDs and modern file systems. The protective
principle is encryption instead of deletion; PQKeep deliberately does not delete originals.

**Fingerprints:** confirm a recipient's fingerprint (`pqkeep inspect anna.pub.json`) over a second
channel before encrypting for them.
