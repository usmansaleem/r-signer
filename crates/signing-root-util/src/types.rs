use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Hash256 = primitive_types::H256;
pub type BLSSignature = primitive_types::H768;

#[derive(Error, Debug)]
pub enum SigningRootError {
    #[error("Unexpected Error in converting vector to array")]
    VectorConversionError,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body_root: Hash256,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct Fork {
    #[serde(with = "eth2_serde_utils::bytes_4_hex")]
    pub previous_version: [u8; 4],
    #[serde(with = "eth2_serde_utils::bytes_4_hex")]
    pub current_version: [u8; 4],
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub epoch: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,
    pub beacon_block_root: Hash256,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct AggregationSlot {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub slot: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub epoch: u64,
    pub root: Hash256,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(with = "eth2_serde_utils::hex_vec")]
    pub aggregation_bits: Vec<u8>,
    pub data: AttestationData,
    pub signature: BLSSignature,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct AggregateAndProof {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: Attestation,
    pub selection_proof: BLSSignature,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct RandaoReveal {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub epoch: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct VoluntaryExit {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub epoch: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
}
