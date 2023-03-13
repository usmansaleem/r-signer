use serde::{Deserialize, Serialize};
use serde_aux::prelude::deserialize_number_from_string;
use serde_hex::{SerHex, StrictPfx};
use thiserror::Error;

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct Bytes4(#[serde(with = "SerHex::<StrictPfx>")] pub [u8; 4]);

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct Bytes32(#[serde(with = "SerHex::<StrictPfx>")] pub [u8; 32]);

#[derive(Error, Debug)]
pub enum SigningRootError {
    #[error("Unexpected Error in converting vector to array")]
    VectorConversionError,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub slot: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub proposer_index: u64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct Fork {
    pub previous_version: Bytes4,
    pub current_version: Bytes4,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub epoch: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Bytes32,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub slot: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub index: u64,
    pub beacon_block_root: Bytes32,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct AggregationSlot {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub slot: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub epoch: u64,
    pub root: Bytes32,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct RandaoReveal {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub epoch: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct VoluntaryExit {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub epoch: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub validator_index: u64,
}
