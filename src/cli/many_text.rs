//! DE: Texte für mehrere Quellen bei `encrypt`/`decrypt` (Mehrfachauswahl).
//! EN: Texts for several sources with `encrypt`/`decrypt` (multi-selection).

use pqkeep::security::Lang;

/// DE: Texte einer Sprache. EN: Texts of one language.
#[allow(missing_docs)]
pub struct ManyTexts {
    pub arg_sources: &'static str,
    pub arg_encrypted: &'static str,
    pub arg_each: &'static str,
    pub arg_rename: &'static str,
    pub need_out: &'static str,
    pub no_out: &'static str,
    pub mixed: &'static str,
    pub failed: &'static str,
    pub summary: &'static str,
}

static DE: ManyTexts = ManyTexts {
    arg_sources: "Datei(en) oder Ordner (bis 1000); mehrere: mit --out ein Container, mit --each jede einzeln",
    arg_encrypted: "Verschlüsselte Datei(en) (.pqkf, bis 1000); mehrere werden einzeln neben sich entschlüsselt",
    arg_each: "Jede Quelle einzeln verschlüsseln (Ziel jeweils daneben, Passphrase nur einmal)",
    arg_rename: "Ist das Standardziel belegt, freien Namen wählen (z. B. „bericht (2).pdf“)",
    need_out: "Mehrere Quellen: --out <container.pqkf> für einen Container oder --each für einzelne Dateien angeben.",
    no_out: "Mehrere Dateien werden einzeln neben sich entschlüsselt; --out ist dann nicht möglich.",
    mixed: "Die Dateien sind unterschiedlich geschützt (Passphrase/Empfänger). Bitte getrennt entschlüsseln.",
    failed: "Fehlgeschlagen",
    summary: "Erledigt",
};

static EN: ManyTexts = ManyTexts {
    arg_sources: "File(s) or folder(s) (up to 1000); several: one container with --out, each separately with --each",
    arg_encrypted: "Encrypted file(s) (.pqkf, up to 1000); several are decrypted separately next to themselves",
    arg_each: "Encrypt each source separately (target next to it, passphrase only once)",
    arg_rename: "If the default target exists, choose a free name (e.g. \"report (2).pdf\")",
    need_out: "Several sources: pass --out <container.pqkf> for one container or --each for separate files.",
    no_out: "Several files are decrypted separately next to themselves; --out is not possible then.",
    mixed: "The files are protected differently (passphrase/recipient). Please decrypt them separately.",
    failed: "Failed",
    summary: "Done",
};

/// DE: Texte für `lang`. EN: Texts for `lang`.
pub fn many_texts(lang: Lang) -> &'static ManyTexts {
    if lang == Lang::De { &DE } else { &EN }
}
