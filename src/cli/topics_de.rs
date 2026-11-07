//! DE: Hilfethemen auf Deutsch. EN: Help topics in German.

/// DE: (Name, Text). EN: (name, text).
pub const TOPICS: [(&str, &str); 6] = [
    (
        "passphrase",
        "PASSPHRASE\n\n\
Regeln für neue Passphrasen:\n\
  - mindestens 16, höchstens 1024 Zeichen (Unicode-Zeichen nach NFKC, nicht Bytes)\n\
  - Klein- und Großbuchstabe, Ziffer, Sonderzeichen (Leer- und Satzzeichen zählen)\n\
  - keine Wiederholungen (aaaa), Folgen (1234, abcd) oder Tastaturreihen (qwertz)\n\
  - häufige Passwörter/Wörter dürfen höchstens ein Drittel ausmachen\n\
  - geschätzte Stärke mindestens 80 Bit\n\n\
Eingabe nur verdeckt im Terminal oder über --passphrase-stdin, nie als Argument.\n\
Am sichersten: pqkeep passphrase (24 Zeichen, ca. 157 Bit).\n\n\
Beispiel:\n  pqkeep passphrase --length 32 --no-ambiguous",
    ),
    (
        "algorithms",
        "ALGORITHMEN\n\n\
  ML-KEM-512/768/1024  Schlüsselaustausch (FIPS 203), Standard ML-KEM-768\n\
  ML-DSA-44/65/87      Signaturen (FIPS 204), Standard ML-DSA-65\n\
  AES-256              symmetrischer Schlüssel; Dateien: AES-256-GCM\n\
  Argon2id             Schlüsselableitung aus der Passphrase (256 MiB bzw. 1 GiB)\n\n\
Private Schlüssel werden als kompakter Seed gespeichert. Die Bibliotheken sind nicht\n\
FIPS-140-validiert und nicht extern auditiert.\n\n\
Beispiel:\n  pqkeep generate --algorithm ml-kem-1024 --name \"Max Muster\" --out max.key.json",
    ),
    (
        "container",
        "CONTAINER (SCHLÜSSELDATEI)\n\n\
JSON-Datei mit Algorithmus, Fingerabdruck, Erstellungszeit, Metadaten, öffentlichem\n\
Schlüssel und dem mit Passphrase verschlüsselten privaten Teil.\n\
ACHTUNG: Metadaten (Name, Organisation …) sind NICHT verschlüsselt, nur gegen\n\
Änderung geschützt. Linux: Rechte 0600.\n\
*.pub.json enthält nur den öffentlichen Teil und darf weitergegeben werden.\n\n\
Beispiel:\n  pqkeep inspect max.key.json",
    ),
    (
        "files",
        "DATEIEN UND ORDNER\n\n\
pqkeep encrypt verschlüsselt eine Datei oder einen ganzen Ordner (rekursiv) in eine\n\
.pqkf-Datei: mit Passphrase oder mit --to für einen Empfänger (ML-KEM).\n\
Symlinks, Geräte und nicht portable Namen werden übersprungen und gemeldet.\n\
Beim Entschlüsseln wird nichts überschrieben und bei Fehlern nichts hinterlassen.\n\
Sichtbar bleibt die ungefähre Größe. Zeitstempel und Rechte werden nicht übernommen.\n\
Originale werden nicht gelöscht.\n\n\
Beispiel:\n  pqkeep encrypt Ordner --to anna.pub.json\n  pqkeep decrypt Ordner.pqkf --key anna.key.json",
    ),
    (
        "security",
        "SICHERHEIT UND GRENZEN\n\n\
  - Speicherseiten mit Geheimnissen werden gesperrt (kein Swap), Core Dumps unter Linux\n\
    abgeschaltet, Geheimnisse nach Gebrauch genullt – alles nach bestem Bemühen.\n\
  - Schutz gilt gegen Diebstahl von Dateien, nicht gegen Schadsoftware auf dem Rechner.\n\
  - Empfohlen: Festplattenverschlüsselung, verschlüsselter Swap, kein Ruhezustand.\n\
  - Fingerabdruck öffentlicher Schlüssel immer auf einem zweiten Weg abgleichen.\n\
  - Nicht als root/Administrator ausführen.\n\n\
Beispiel:\n  pqkeep --verbose inspect max.key.json",
    ),
    (
        "verify",
        "RELEASES PRÜFEN\n\n\
Jedes Release (auch Betas) wird signiert und mit Prüfsummen veröffentlicht.\n\
  sha256sum -c SHA256SUMS\n\
  gh attestation verify <datei> --repo SpecterAoD/pqkeep\n\
  cosign verify-blob … (siehe README)\n\
Windows: Authenticode-Signatur in den Dateieigenschaften prüfen (sobald verfügbar).\n\n\
Beispiel:\n  sha256sum -c SHA256SUMS",
    ),
];
