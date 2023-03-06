//! Library to encrypt and decrypt BLS12-381 Keystores.
//! The keystore is in JSON format as defined by [EIP-2335][1].
//!
//![1]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md

pub mod keystore;

#[cfg(test)]
mod tests;

use anyhow::Result;
use keystore::KdfParams;
use unicode_normalization::UnicodeNormalization;

/// Decrypt BLS12-381 keystore with provided password. Returns decrypted key
/// as bytes
pub fn decrypt(keystore_json: String, password: String) -> Result<Vec<u8>> {
    let normalized_password = normalize_password(password);
    let keystore = keystore::parse_keystore(keystore_json.as_str())?;
    let decryption_key = match keystore.crypto.kdf {
        KdfParams::SCrypt { params, message: _ } => {
            params.decryption_key(normalized_password.as_str())
        }
        KdfParams::PbKdf2 { params, message: _ } => {
            params.decryption_key(normalized_password.as_str())
        }
    };
    //FIXME
    let decoded = hex::decode("0x0")?;
    Ok(decoded)
}

fn normalize_password(password: String) -> String {
    password
        .nfkd()
        .collect::<String>()
        .chars()
        .filter(|c| !is_control(c))
        .collect::<String>()
}

fn is_c0(c: &char) -> bool {
    *c >= '\u{0000}' && *c <= '\u{001F}'
}

fn is_c1(c: &char) -> bool {
    *c >= '\u{0080}' && *c <= '\u{009F}'
}

fn is_control(c: &char) -> bool {
    is_c0(c) || is_c1(c) || *c == '\u{007F}'
}
