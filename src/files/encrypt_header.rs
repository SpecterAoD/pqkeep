//! DE: Header beim Verschlüsseln: v1, wenn ein einzelner Zugang ohne Faktordatei genügt (ältere
//! Versionen bleiben lesefähig), sonst v2; mit Absender immer v3 (`docs/V3_SIGNED.md`).
//! EN: Header when encrypting: v1 if a single slot without factor file suffices (older versions
//! can still read it), else v2; with a sender always v3 (`docs/V3_SIGNED.md`).

use super::encrypt_v2;
use super::format::{Content, FileHeader, HeaderMode};
use super::{PassphraseAccess, Protection};
use crate::crypto::kdf::{KdfParams, SALT_LEN};
use crate::crypto::stream::PREFIX_LEN;
use crate::crypto::wrap::{self, Wrapped};
use crate::crypto::{KeyAlgorithm, SecretBytes, rng};
use crate::envelope::{KEY_ID_LEN, PublicKeyFile};
use crate::security::StrongPassphrase;
use crate::{Error, Result};

/// DE: Kodierter Header und Strom-AAD. Schreibt v1, wenn ein einzelner Zugang ohne Faktordatei
/// genügt (ältere Versionen bleiben lesefähig), sonst v2.
/// EN: Encoded header and stream AAD. Writes v1 if a single slot without factor file suffices
/// (older versions can still read it), else v2.
pub(super) fn build(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    protection: &Protection<'_>,
    file_key: &SecretBytes,
    signer: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if signer.is_some() || content == Content::Stream {
        // DE: Mit Absender immer v3, Ströme immer v4 (auch bei einem einzelnen Zugang).
        // EN: With a sender always v3, streams always v4 (even for a single slot).
        let header = v3_header(content, prefix, protection, file_key, signer)?;
        return Ok((header.encode()?, header.stream_aad()?));
    }
    let v1 = match protection {
        Protection::Passphrase { passphrase, params }
        | Protection::Slots {
            passphrase:
                Some(PassphraseAccess {
                    passphrase,
                    params,
                    factor: None,
                }),
            recipients: [],
        } => passphrase_header(content, prefix, passphrase, params, file_key)?,
        Protection::Recipient(key)
        | Protection::Slots {
            passphrase: None,
            recipients: [key],
        } => recipient_header(content, prefix, key, file_key)?,
        Protection::Slots {
            passphrase,
            recipients,
        } => {
            let header = encrypt_v2::build(
                content,
                prefix,
                passphrase.as_ref(),
                recipients,
                file_key,
                signer,
            )?;
            return Ok((header.encode()?, header.stream_aad()?));
        }
    };
    Ok((v1.encode(), v1.stream_aad()))
}

/// DE: v3-Header: jeder Schutz als Zugänge wie v2. EN: v3 header: every protection as v2 slots.
fn v3_header(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    protection: &Protection<'_>,
    file_key: &SecretBytes,
    signer: Option<&[u8]>,
) -> Result<super::HeaderV2> {
    match protection {
        Protection::Passphrase { passphrase, params } => {
            let access = PassphraseAccess {
                passphrase,
                params: *params,
                factor: None,
            };
            encrypt_v2::build(content, prefix, Some(&access), &[], file_key, signer)
        }
        Protection::Recipient(key) => {
            encrypt_v2::build(content, prefix, None, &[*key], file_key, signer)
        }
        Protection::Slots {
            passphrase,
            recipients,
        } => encrypt_v2::build(
            content,
            prefix,
            passphrase.as_ref(),
            recipients,
            file_key,
            signer,
        ),
    }
}

fn placeholder() -> Wrapped {
    Wrapped {
        nonce: [0; 12],
        ciphertext: Vec::new(),
    }
}

fn passphrase_header(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    passphrase: &StrongPassphrase,
    params: &KdfParams,
    file_key: &SecretBytes,
) -> Result<FileHeader> {
    let salt = rng::array::<SALT_LEN>()?.to_vec();
    let mut header = FileHeader {
        content,
        prefix,
        mode: HeaderMode::Passphrase {
            params: *params,
            salt: salt.clone(),
        },
        wrapped: placeholder(),
    };
    let aad = header.wrap_aad();
    header.wrapped =
        wrap::wrap_with_passphrase(passphrase, params, &salt, file_key.expose(), &aad)?;
    Ok(header)
}

fn recipient_header(
    content: Content,
    prefix: [u8; PREFIX_LEN],
    key: &PublicKeyFile,
    file_key: &SecretBytes,
) -> Result<FileHeader> {
    let KeyAlgorithm::Kem(algorithm) = key.algorithm() else {
        return Err(Error::InvalidInput { field: "recipient" });
    };
    let recipient_id: [u8; KEY_ID_LEN] = key
        .key_id()
        .try_into()
        .map_err(|_| Error::InvalidInput { field: "recipient" })?;
    let mut header = FileHeader {
        content,
        prefix,
        mode: HeaderMode::Recipient {
            algorithm,
            recipient_id,
            kem_ciphertext: Vec::new(),
        },
        wrapped: placeholder(),
    };
    // DE: AAD ohne KEM-Chiffrat; dieses ist über HKDF (Salt) gebunden.
    // EN: AAD without the KEM ciphertext; it is bound via HKDF (salt).
    let aad = header.wrap_aad();
    let r = wrap::wrap_for_recipient(
        algorithm,
        key.public_key(),
        &recipient_id,
        file_key.expose(),
        &aad,
    )?;
    header.mode = HeaderMode::Recipient {
        algorithm,
        recipient_id,
        kem_ciphertext: r.kem_ciphertext,
    };
    header.wrapped = r.wrapped;
    Ok(header)
}
