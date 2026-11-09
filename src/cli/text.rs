//! DE: Alle Texte der CLI als Struktur; je eine vollständige Instanz für Deutsch
//! und Englisch (`text_de.rs`, `text_en.rs`). Fehlt ein Text, kompiliert es nicht.
//! EN: All CLI texts as a struct; one complete instance each for German and
//! English (`text_de.rs`, `text_en.rs`). A missing text fails to compile.

use pqkeep::security::Lang;

/// DE: Texte einer Sprache. EN: Texts of one language.
#[allow(missing_docs)]
pub struct Texts {
    pub app_about: &'static str,
    pub app_after: &'static str,
    pub arg_lang: &'static str,
    pub arg_verbose: &'static str,
    pub gen_about: &'static str,
    pub gen_after: &'static str,
    pub arg_algorithm: &'static str,
    pub arg_name: &'static str,
    pub arg_org: &'static str,
    pub arg_company: &'static str,
    pub arg_department: &'static str,
    pub arg_account_type: &'static str,
    pub arg_profile: &'static str,
    pub arg_out: &'static str,
    pub arg_passphrase_stdin: &'static str,
    pub arg_passphrase_file: &'static str,
    pub arg_batch: &'static str,
    pub arg_force: &'static str,
    pub arg_yes: &'static str,
    pub validate_about: &'static str,
    pub validate_after: &'static str,
    pub pass_about: &'static str,
    pub pass_after: &'static str,
    pub arg_length: &'static str,
    pub arg_count: &'static str,
    pub arg_min_bits: &'static str,
    pub rate_weak: &'static str,
    pub rate_good: &'static str,
    pub rate_strong: &'static str,
    pub arg_no_ambiguous: &'static str,
    pub inspect_about: &'static str,
    pub inspect_after: &'static str,
    pub arg_file: &'static str,
    pub export_about: &'static str,
    pub export_after: &'static str,
    pub arg_keyfile: &'static str,
    pub prompt_passphrase: &'static str,
    pub prompt_new_passphrase: &'static str,
    pub prompt_confirm: &'static str,
    pub prompt_mismatch: &'static str,
    pub prompt_overwrite: &'static str,
    pub msg_no_tty: &'static str,
    pub msg_need_name_out: &'static str,
    pub msg_aborted: &'static str,
    pub msg_created: &'static str,
    pub msg_exported: &'static str,
    pub msg_fingerprint: &'static str,
    pub msg_metadata_plaintext: &'static str,
    pub msg_verify_fingerprint: &'static str,
    pub msg_rejected: &'static str,
    pub msg_strong: &'static str,
    pub msg_entropy: &'static str,
    pub msg_generated_hint: &'static str,
    pub msg_root_warning: &'static str,
    pub msg_hardening: &'static str,
    pub msg_error: &'static str,
    pub msg_warning: &'static str,
    pub lbl_type: &'static str,
    pub type_key: &'static str,
    pub type_public: &'static str,
    pub type_encrypted: &'static str,
    pub lbl_algorithm: &'static str,
    pub lbl_key_id: &'static str,
    pub lbl_created: &'static str,
    pub lbl_name: &'static str,
    pub lbl_organization: &'static str,
    pub lbl_company: &'static str,
    pub lbl_department: &'static str,
    pub lbl_account_type: &'static str,
    pub lbl_kdf: &'static str,
    pub lbl_content: &'static str,
    pub lbl_mode: &'static str,
    pub lbl_recipient: &'static str,
    pub content_file: &'static str,
    pub content_dir: &'static str,
    pub mode_passphrase: &'static str,
    pub mode_recipient: &'static str,
    pub enc_about: &'static str,
    pub enc_after: &'static str,
    pub dec_about: &'static str,
    pub dec_after: &'static str,
    pub arg_out_optional: &'static str,
    pub arg_to: &'static str,
    pub arg_key: &'static str,
    pub help_about: &'static str,
    pub arg_topic: &'static str,
    pub help_after: &'static str,
    pub compl_about: &'static str,
    pub compl_after: &'static str,
    pub arg_shell: &'static str,
    pub man_about: &'static str,
    pub man_after: &'static str,
    pub heading_usage: &'static str,
    pub heading_options: &'static str,
    pub flag_help: &'static str,
    pub flag_version: &'static str,
    pub msg_usage_error: &'static str,
    pub msg_encrypted: &'static str,
    pub msg_decrypted: &'static str,
    pub msg_summary: &'static str,
    pub msg_skipped: &'static str,
    pub skip_symlink: &'static str,
    pub skip_special: &'static str,
    pub skip_non_utf8: &'static str,
    pub skip_invalid: &'static str,
    pub prompt_key_passphrase: &'static str,
    pub msg_need_key: &'static str,
    pub msg_no_key_needed: &'static str,
    pub msg_unknown_topic: &'static str,
    pub menu_title: &'static str,
    pub menu_items: &'static str,
    pub menu_path: &'static str,
    pub menu_out: &'static str,
    pub menu_recipient: &'static str,
    pub menu_keyfile: &'static str,
    pub menu_hint_passphrase: &'static str,
    pub menu_pass_len: &'static str,
}

/// DE: Texte der gewählten Sprache. EN: Texts of the chosen language.
pub fn texts(lang: Lang) -> &'static Texts {
    match lang {
        Lang::De => &super::text_de::DE,
        Lang::En => &super::text_en::EN,
    }
}

/// DE: Gemeinsamer Abschnitt Exit-Codes. EN: Shared exit code section.
pub fn exit_codes(lang: Lang) -> &'static str {
    match lang {
        Lang::De => {
            "Exit-Codes:\n  0  Erfolg\n  1  Fehler\n  2  Bedienfehler (Argumente)\n  3  Entschlüsselung fehlgeschlagen (falsche Passphrase/Schlüssel oder Manipulation)\n  4  Passphrase zu schwach\n  5  Ziel existiert bereits"
        }
        Lang::En => {
            "Exit codes:\n  0  success\n  1  error\n  2  usage error (arguments)\n  3  decryption failed (wrong passphrase/key or tampering)\n  4  passphrase too weak\n  5  target already exists"
        }
    }
}
