//! Library to encrypt and decrypt BLS12-381 Keystores.
//! The keystore is in JSON format as defined by [EIP-2335][1].
//!
//![1]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md

#[cfg(test)]
mod tests;

use unicode_normalization::UnicodeNormalization;

/// Decrypt BLS12-381 keystore with provided password. Returns decrypted key
/// as hex string.
pub fn decrypt(keystore_json: String, password: String) -> Result<String, String> {
    let n_password = normalize_password(password);
    return Ok(String::from("0x0"));
}

fn normalize_password(password: String) -> String {
    password.nfkd().collect::<String>()
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}
