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
