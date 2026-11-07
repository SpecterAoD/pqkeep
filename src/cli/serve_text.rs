//! DE: Texte für `keyforge serve` (nur mit Feature `api`).
//! EN: Texts for `keyforge serve` (feature `api` only).

use pqc_keyforge::security::Lang;

/// DE: Texte einer Sprache. EN: Texts of one language.
#[allow(missing_docs)]
pub struct ServeTexts {
    pub about: &'static str,
    pub after: &'static str,
    pub arg_bind: &'static str,
    pub arg_token_file: &'static str,
    pub arg_allow_remote: &'static str,
    pub arg_init_token: &'static str,
    pub arg_force: &'static str,
    pub msg_token_created: &'static str,
    pub msg_bad_bind: &'static str,
    pub msg_remote_refused: &'static str,
    pub msg_remote_warning: &'static str,
    pub msg_listening: &'static str,
    pub msg_stopped: &'static str,
}

static DE: ServeTexts = ServeTexts {
    about: "REST-API starten (POST /v1/validate, GET /v1/health)",
    after: "Beispiele:\n  keyforge serve --init-token --token-file api.token\n  keyforge serve --token-file api.token\n  keyforge serve --token-file api.token --bind 127.0.0.1:9000\n\nAnfragen brauchen den Header „Authorization: Bearer <Token>“ (außer /v1/health).\nDie Token-Datei enthält nur einen Hash; das Token wird beim Anlegen einmal angezeigt.\nKein TLS eingebaut: für Zugriff über das Netz einen Reverse Proxy mit TLS davorschalten.",
    arg_bind: "Adresse:Port (Standard 127.0.0.1:8787)",
    arg_token_file: "Datei mit dem Token-Hash (Pflicht)",
    arg_allow_remote: "Andere Adressen als localhost erlauben (nur hinter Reverse Proxy mit TLS!)",
    arg_init_token: "Neues Token erzeugen, Hash speichern, Token einmal anzeigen und beenden",
    arg_force: "Vorhandene Token-Datei ersetzen (altes Token wird ungültig)",
    msg_token_created: "Token erzeugt. Es wird nur jetzt angezeigt – sicher aufbewahren. Gespeichert ist nur der Hash.",
    msg_bad_bind: "Ungültige Adresse (Format Adresse:Port, z. B. 127.0.0.1:8787)",
    msg_remote_refused: "Adresse ist nicht localhost. Nur mit --allow-remote und Reverse Proxy mit TLS.",
    msg_remote_warning: "WARNUNG: API ist über das Netz erreichbar und spricht nur HTTP. Token und Passphrasen nur über einen Reverse Proxy mit TLS senden.",
    msg_listening: "API läuft auf",
    msg_stopped: "API beendet.",
};

static EN: ServeTexts = ServeTexts {
    about: "Start the REST API (POST /v1/validate, GET /v1/health)",
    after: "Examples:\n  keyforge serve --init-token --token-file api.token\n  keyforge serve --token-file api.token\n  keyforge serve --token-file api.token --bind 127.0.0.1:9000\n\nRequests need the header \"Authorization: Bearer <token>\" (except /v1/health).\nThe token file holds a hash only; the token is shown once when created.\nNo built-in TLS: for network access put a reverse proxy with TLS in front.",
    arg_bind: "Address:port (default 127.0.0.1:8787)",
    arg_token_file: "File with the token hash (required)",
    arg_allow_remote: "Allow addresses other than localhost (only behind a reverse proxy with TLS!)",
    arg_init_token: "Create a new token, store its hash, show the token once and exit",
    arg_force: "Replace an existing token file (the old token becomes invalid)",
    msg_token_created: "Token created. It is shown only now – keep it safe. Only the hash is stored.",
    msg_bad_bind: "Invalid address (format address:port, e.g. 127.0.0.1:8787)",
    msg_remote_refused: "Address is not localhost. Only with --allow-remote and a reverse proxy with TLS.",
    msg_remote_warning: "WARNING: the API is reachable over the network and speaks plain HTTP only. Send tokens and passphrases only via a reverse proxy with TLS.",
    msg_listening: "API listening on",
    msg_stopped: "API stopped.",
};

/// DE: Texte der gewählten Sprache. EN: Texts of the chosen language.
pub fn serve_texts(lang: Lang) -> &'static ServeTexts {
    match lang {
        Lang::De => &DE,
        Lang::En => &EN,
    }
}
