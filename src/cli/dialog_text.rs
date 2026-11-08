//! DE: Texte der Kontextmenü-Fenster (`pqkeep context --dialog`).
//! EN: Texts of the context menu windows (`pqkeep context --dialog`).

use pqkeep::security::Lang;

/// DE: Texte einer Sprache. EN: Texts of one language.
#[allow(missing_docs)]
pub struct DialogTexts {
    pub title: &'static str,
    pub cancel: &'static str,
    pub arg_dialog: &'static str,
    pub pass: &'static str,
    pub new_pass: &'static str,
    pub first: &'static str,
    pub second: &'static str,
    pub key_pass: &'static str,
    pub pick_pub: &'static str,
    pub pick_key: &'static str,
    pub filter_pub: &'static str,
    pub filter_key: &'static str,
    pub working: &'static str,
    pub step: &'static str,
    pub done: &'static str,
    pub incomplete: &'static str,
    pub failed: &'static str,
    pub retry: &'static str,
    pub no_tool: &'static str,
}

static DE: DialogTexts = DialogTexts {
    title: "PQKeep",
    cancel: "Abbrechen",
    arg_dialog: "Kleine Fenster statt Terminal verwenden (Linux: zenity oder kdialog, Windows: PowerShell)",
    pass: "Passphrase",
    new_pass: "Neue Passphrase für die verschlüsselte Datei (mindestens 80 Bit, z. B. vier bis fünf zufällige Wörter)",
    first: "Passphrase",
    second: "Wiederholen",
    key_pass: "Passphrase der eigenen Schlüsseldatei",
    pick_pub: "Öffentliche Schlüsseldatei des Empfängers wählen",
    pick_key: "Eigene Schlüsseldatei wählen",
    filter_pub: "Öffentliche Schlüssel (*.pub.json)",
    filter_key: "Schlüsseldateien (*.json)",
    working: "Bitte warten …",
    step: "Datei {i} von {n}",
    done: "Fertig. Gespeichert unter:",
    incomplete: "Achtung – nicht alles wurde übernommen. Originale erst löschen, wenn das geprüft ist:",
    failed: "Fehlgeschlagen.",
    retry: "Erneut versuchen?",
    no_tool: "Kein Fenster-Werkzeug (zenity, kdialog bzw. PowerShell mit Windows Forms) oder keine grafische Sitzung gefunden.",
};

static EN: DialogTexts = DialogTexts {
    title: "PQKeep",
    cancel: "Cancel",
    arg_dialog: "Use small windows instead of a terminal (Linux: zenity or kdialog, Windows: PowerShell)",
    pass: "Passphrase",
    new_pass: "New passphrase for the encrypted file (at least 80 bits, e.g. four to five random words)",
    first: "Passphrase",
    second: "Repeat",
    key_pass: "Passphrase of your own key file",
    pick_pub: "Choose the recipient's public key file",
    pick_key: "Choose your own key file",
    filter_pub: "Public keys (*.pub.json)",
    filter_key: "Key files (*.json)",
    working: "Please wait …",
    step: "File {i} of {n}",
    done: "Done. Saved as:",
    incomplete: "Warning – not everything was included. Only delete originals after checking this:",
    failed: "Failed.",
    retry: "Try again?",
    no_tool: "No window tool (zenity, kdialog or PowerShell with Windows Forms) or no graphical session found.",
};

/// DE: Texte für `lang`. EN: Texts for `lang`.
pub fn dialog_texts(lang: Lang) -> &'static DialogTexts {
    if lang == Lang::De { &DE } else { &EN }
}
