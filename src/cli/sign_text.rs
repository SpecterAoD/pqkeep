//! DE: Texte für `pqkeep sign` und `pqkeep verify`. EN: Texts for `pqkeep sign` and `pqkeep verify`.

use pqkeep::security::Lang;

/// DE: Texte einer Sprache. EN: Texts of one language.
#[allow(missing_docs)]
pub struct SignTexts {
    pub sign_about: &'static str,
    pub sign_after: &'static str,
    pub verify_about: &'static str,
    pub verify_after: &'static str,
    pub arg_file: &'static str,
    pub arg_key: &'static str,
    pub arg_out: &'static str,
    pub arg_pub: &'static str,
    pub arg_sig: &'static str,
    pub need_ml_dsa_87: &'static str,
    pub signed: &'static str,
    pub fingerprint: &'static str,
    pub signer: &'static str,
    pub time: &'static str,
    pub note: &'static str,
    pub invalid: &'static str,
    pub other_key: &'static str,
}

static DE: SignTexts = SignTexts {
    sign_about: "Datei signieren (ML-DSA-87, abgesetzte Signatur .pqsig)",
    sign_after: "Beispiel:\n  pqkeep sign --key anna.key.json vertrag.pdf      (→ vertrag.pdf.pqsig)\n\nSigniert wird der SHA3-512 der Datei (gestreamt); der Dateiname gehört nicht dazu.\nNur ML-DSA-87-Schlüssel (pqkeep generate -a ml-dsa-87). Keine qualifizierte\nelektronische Signatur nach eIDAS. Format: docs/SIGNATURE_FORMAT.md",
    verify_about: "Signatur einer Datei prüfen ([VERIFIED] oder [INVALID])",
    verify_after: "Beispiel:\n  pqkeep verify --pub anna.pub.json vertrag.pdf     (liest vertrag.pdf.pqsig)\n\nExit-Code 0 = gültig, 7 = ungültig. Gültig heißt: Datei unverändert und vom Inhaber des\nprivaten Schlüssels signiert. WER das ist, nur über den Fingerabdruck auf einem zweiten Weg\nbestätigen. Der Zeitpunkt ist eine Angabe des Signierers. Keine eIDAS-Signatur.",
    arg_file: "Datei",
    arg_key: "Eigene Schlüsseldatei (ML-DSA-87, .key.json)",
    arg_out: "Signaturdatei (Standard: <datei>.pqsig)",
    arg_pub: "Öffentlicher Schlüssel des Signierers (.pub.json)",
    arg_sig: "Signaturdatei (Standard: <datei>.pqsig)",
    need_ml_dsa_87: "Für Signaturen wird ein ML-DSA-87-Schlüssel benötigt (pqkeep generate -a ml-dsa-87).",
    signed: "Signiert",
    fingerprint: "Fingerabdruck (Schlüssel-ID) des Signierers",
    signer: "Signierer (Schlüssel-ID)",
    time: "Zeitpunkt laut Signierer",
    note: "Hinweis: Identität des Signierers nur über den Fingerabdruck bestätigen; keine eIDAS-Signatur.",
    invalid: "Datei verändert, falscher Schlüssel oder manipulierte Signatur.",
    other_key: "Die Signatur stammt von einem anderen Schlüssel",
};

static EN: SignTexts = SignTexts {
    sign_about: "Sign a file (ML-DSA-87, detached signature .pqsig)",
    sign_after: "Example:\n  pqkeep sign --key anna.key.json contract.pdf      (→ contract.pdf.pqsig)\n\nThe SHA3-512 of the file is signed (streamed); the file name is not part of it.\nML-DSA-87 keys only (pqkeep generate -a ml-dsa-87). Not a qualified electronic\nsignature under eIDAS. Format: docs/SIGNATURE_FORMAT.md",
    verify_about: "Verify a file's signature ([VERIFIED] or [INVALID])",
    verify_after: "Example:\n  pqkeep verify --pub anna.pub.json contract.pdf    (reads contract.pdf.pqsig)\n\nExit code 0 = valid, 7 = invalid. Valid means: file unchanged and signed by the holder of\nthe private key. WHO that is must be confirmed via the fingerprint through a second channel.\nThe time is the signer's claim. Not an eIDAS signature.",
    arg_file: "File",
    arg_key: "Your own key file (ML-DSA-87, .key.json)",
    arg_out: "Signature file (default: <file>.pqsig)",
    arg_pub: "Signer's public key (.pub.json)",
    arg_sig: "Signature file (default: <file>.pqsig)",
    need_ml_dsa_87: "Signatures need an ML-DSA-87 key (pqkeep generate -a ml-dsa-87).",
    signed: "Signed",
    fingerprint: "Signer's fingerprint (key ID)",
    signer: "Signer (key ID)",
    time: "Time claimed by the signer",
    note: "Note: confirm the signer's identity via the fingerprint only; not an eIDAS signature.",
    invalid: "File changed, wrong key or tampered signature.",
    other_key: "The signature was made with a different key",
};

/// DE: Texte für `lang`. EN: Texts for `lang`.
pub fn sign_texts(lang: Lang) -> &'static SignTexts {
    if lang == Lang::De { &DE } else { &EN }
}
