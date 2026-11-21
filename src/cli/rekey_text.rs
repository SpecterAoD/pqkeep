//! DE: Texte des Rekey-Befehls. EN: Rekey command texts.
use pqkeep::security::Lang;

pub(super) struct Texts {
    pub about: &'static str,
    pub after: &'static str,
    pub out: &'static str,
    pub backup: &'static str,
    pub stdin: &'static str,
    pub changed: &'static str,
    pub hint: &'static str,
    pub input: &'static str,
    pub pass_file: &'static str,
}

const DE: Texts = Texts {
    about: "Passphrase einer Schlüsseldatei ändern; Schlüssel und ID bleiben gleich",
    after: "Beispiel: pqkeep rekey anna.key.json --out anna.neu.key.json\nAustausch: pqkeep rekey anna.key.json --out anna.key.json --backup anna.alt.key.json --force\nVerdeckte Eingabe: alte Passphrase, neue Passphrase mit Bestätigung. Stdin: genau drei Zeilen (alt, neu, Bestätigung), danach EOF. Bei v2 dieselbe Faktordatei angeben. KDF und Format bleiben gleich. Neue Ziele und Sicherungen benötigen Hardlinks. Austausch nur mit neuer Sicherung und Bestätigung; --force --yes für Batch. Alte Kopien behalten ihren alten Schutz. Keine Stromausfallgarantie. Details: docs/REKEY.md.",
    out: "Neuer Zielpfad; derselbe Quellpfad nur mit --force und --backup",
    backup: "Neue separate Sicherung der alten verschlüsselten Datei; niemals überschreiben",
    stdin: "Drei begrenzte Zeilen von stdin: alte, neue Passphrase, Bestätigung; danach EOF",
    changed: "Passphrase-Schutz erneuert",
    hint: "Alte Kopien und Sicherungen bleiben mit der alten Passphrase nutzbar. Sicher aufbewahren; kein Widerruf alter Kopien.",
    input: "Rekey-Eingabe ungültig: drei UTF-8-Zeilen mit jeweils höchstens 4 KiB, danach EOF erforderlich.",
    pass_file: "rekey unterstützt --passphrase-file nicht. Verdeckte Eingabe oder --passphrase-stdin mit drei Zeilen verwenden.",
};
const EN: Texts = Texts {
    about: "Change a key file passphrase; keep the same key and ID",
    after: "Example: pqkeep rekey jane.key.json --out jane.new.key.json\nReplace: pqkeep rekey jane.key.json --out jane.key.json --backup jane.old.key.json --force\nHidden input: old passphrase, new passphrase with confirmation. Stdin: exactly three lines (old, new, confirmation), then EOF. For v2 supply the same factor file. KDF and format stay unchanged. New outputs and backups require hard links. Replacement requires a new backup and confirmation; --force --yes for batch. Old copies keep their old protection. No power-loss guarantee. Details: docs/REKEY.md.",
    out: "New output path; same source path only with --force and --backup",
    backup: "New separate backup of the old encrypted file; never overwritten",
    stdin: "Three bounded stdin lines: old, new passphrase, confirmation; then EOF",
    changed: "Passphrase protection renewed",
    hint: "Old copies and backups remain usable with the old passphrase. Store safely; old copies are not revoked.",
    input: "Invalid rekey input: three UTF-8 lines of at most 4 KiB each, then EOF required.",
    pass_file: "rekey does not support --passphrase-file. Use hidden input or --passphrase-stdin with three lines.",
};

pub(super) fn texts(lang: Lang) -> &'static Texts {
    if lang == Lang::De { &DE } else { &EN }
}
