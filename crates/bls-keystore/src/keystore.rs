//! Keystore JSON definition
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct Module {
    pub function: String,
    pub params: HashMap<String, Value>,
    pub message: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(tag = "function")]
pub enum KdfParams {
    #[serde(rename = "scrypt")]
    SCrypt {
        params: SCryptParams,
        message: String,
    },

    #[serde(rename = "pbkdf2")]
    PbKdf2 {
        params: Pbkdf2Params,
        message: String,
    },
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct SCryptParams {
    pub dklen: i32,
    pub n: i32,
    pub p: i32,
    pub r: i32,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Pbkdf2Params {
    pub dklen: i32,
    pub c: i32,
    pub prf: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Crypto {
    pub kdf: KdfParams,
    pub checksum: Module,
    pub cipher: Module,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    pub crypto: Crypto,
    pub description: Option<String>,
    pub pubkey: Option<String>,
    pub path: String,
    pub uuid: String,
    pub version: u8,
}

pub fn parse_keystore(json: &str) -> Result<Keystore> {
    let keystore: Keystore = serde_json::from_str(json)?;
    if keystore.version != 4 {
        Err(anyhow!(
            "Keystore version {} is not supported",
            keystore.version
        ))
    } else {
        Ok(keystore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keystore_json_scrypt_parsed() {
        let keystore_json = r#"{
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
            },
            "description": "This is a test keystore that uses scrypt to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
            }"#;

        let keystore = parse_keystore(keystore_json).unwrap();
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.pubkey, Some("9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()));
        let expected_kdf = KdfParams::SCrypt {
            params: SCryptParams {
                dklen: 32,
                n: 262144,
                p: 1,
                r: 8,
                salt: "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    .to_string(),
            },
            message: "".to_string(),
        };
        assert_eq!(keystore.crypto.kdf, expected_kdf);
    }

    #[test]
    fn keystore_json_parsed_wo_desc_pubkey() {
        let keystore_json = r#"{
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
            },
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
            }"#;

        let keystore = parse_keystore(keystore_json).unwrap();
        assert_eq!(keystore.version, 4);
        assert!(keystore.pubkey.is_none());
    }

    #[test]
    fn keystore_json_pbkdf2_parsed() {
        let keystore_json = r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "pbkdf2",
                        "params": {
                            "dklen": 32,
                            "c": 262144,
                            "prf": "hmac-sha256",
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                    }
                },
                "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/0/0",
                "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
                "version": 4
          }"#;
        let keystore = parse_keystore(keystore_json).unwrap();
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.pubkey, Some("9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()));
        let expected_kdf = KdfParams::PbKdf2 {
            params: Pbkdf2Params {
                dklen: 32,
                c: 262144,
                prf: "hmac-sha256".to_string(),
                salt: "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    .to_string(),
            },
            message: "".to_string(),
        };
        assert_eq!(keystore.crypto.kdf, expected_kdf);
    }
}
