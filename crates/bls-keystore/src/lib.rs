//! Library to encrypt and decrypt BLS12-381 Keystores.
//! The keystore is in JSON format as defined by [EIP-2335][1].
//!
//![1]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md

pub mod keystore;

#[cfg(test)]
mod tests;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Decrypt BLS12-381 keystore with provided password. Returns decrypted key
/// as bytes
pub fn decrypt(keystore_json: &str, password: &str) -> Result<Vec<u8>> {
    let normalized_password = normalize_password(password);
    let keystore = keystore::parse_keystore(keystore_json)?;
    let decryption_key = keystore
        .crypto
        .kdf
        .decryption_key(normalized_password.as_str())?;
    let cipher_message = hex::decode(keystore.crypto.cipher.message)?;
    let checksum_message = hex::decode(keystore.crypto.checksum.message)?;

    if !validate_password(&decryption_key, &cipher_message, &checksum_message) {
        bail!("Password verification failed");
    }

    //FIXME
    let decoded = hex::decode("0x0")?;
    Ok(decoded)
}

fn secret_decryption(
    decryption_key: &[u8],
    cipher_function: &str,
    cipher_message: &[u8],
) -> Result<Vec<u8>> {
    if !cipher_function.eq_ignore_ascii_case("aes-128-ctr") {
        bail!(
            "Unsupported cipher function {}, consider reporting it to support team.",
            cipher_function
        );
    }

    let decoded = hex::decode("0x0")?;
    Ok(decoded)
}

fn validate_password(
    decryption_key: &[u8],
    cipher_message: &[u8],
    checksum_message: &[u8],
) -> bool {
    let dk_slice = &decryption_key[16..32];
    let pre_image = [dk_slice, cipher_message].concat();
    let mut hasher = Sha256::new();
    hasher.update(pre_image);
    let checksum = hasher.finalize();

    checksum.eq(checksum_message.into())
}

fn normalize_password(password: &str) -> String {
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
