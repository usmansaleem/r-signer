use super::*;

#[test]
fn normalize_works_with_space() {
    let input = "test test";
    let result = normalize_password(input);
    assert_eq!(result, String::from("test test"));
}

#[test]
fn normalize_strips_c0_control_chars() {
    let input = "test\u{001F}test";
    let result = normalize_password(input);
    assert_eq!(result, String::from("testtest"));
}

#[test]
fn normalize_strips_c1_control_chars() {
    let input = "test\u{0080}\u{0081}\u{009F}test";
    let result = normalize_password(input);
    assert_eq!(result, "testtest".to_string());
}

#[test]
fn normalize_strips_delete_control_chars() {
    let input = "test\u{007F}test";
    let result = normalize_password(input);
    assert_eq!(result, "testtest".to_string());
}

#[test]
fn normalize_works_with_non_control_char() {
    let input = "test\u{0020}test";
    let result = normalize_password(input);
    assert_eq!(result, String::from("test\u{0020}test"));
}

#[test]
fn password_verified() {
    let keystore_json = r#"
    {
      "crypto" : {
        "kdf" : {
          "function" : "scrypt",
          "params" : {
            "dklen" : 32,
            "n" : 512,
            "p" : 1,
            "r" : 8,
            "salt" : "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
          },
          "message" : ""
        },
        "checksum" : {
          "function" : "sha256",
          "params" : { },
          "message" : "28aea7510466a76c848c2f48649b94bd0170f90badf05480948304838d43acfc"
        },
        "cipher" : {
          "function" : "aes-128-ctr",
          "params" : {
            "iv" : "264daa3f303d7259501c93d997d84fe6"
          },
          "message" : "5f4cbeea80336bd076e8f648d4c6c0f6954ae40babdbab70079fc1cd8bec4a11"
        }
      },
      "pubkey" : "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
      "version" : 4,
      "path" : "m/12381/60/3141592653/589793238",
      "uuid" : "eb329e94-6d98-4999-a773-6162fa0dd13a"
    }"#;

    let normalized_password = normalize_password("𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑");
    let keystore = keystore::parse_keystore(keystore_json).unwrap();
    let decryption_key = keystore
        .crypto
        .kdf
        .decryption_key(normalized_password.as_str())
        .unwrap();
    let cipher_message = hex::decode(keystore.crypto.cipher.message).unwrap();
    let checksum_message = hex::decode(keystore.crypto.checksum.message).unwrap();

    let valid_password = validate_password(&decryption_key, &cipher_message, &checksum_message);
    assert!(valid_password);
}
