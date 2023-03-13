use super::{AttestationData, BeaconBlockHeader};
use anyhow::Result;
use ssz_rs::prelude::*;

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct SszU64(pub u64);

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalBeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl TryFrom<&BeaconBlockHeader> for InternalBeaconBlockHeader {
    type Error = &'static str;

    fn try_from(value: &BeaconBlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: value.parent_root.0,
            state_root: value.state_root.0,
            body_root: value.body_root.0,
        })
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalForkData {
    pub current_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalSigningData {
    pub object_root: Node,
    pub domain: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalCheckpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalAttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: [u8; 32],
    pub source: InternalCheckpoint,
    pub target: InternalCheckpoint,
}

impl TryFrom<&AttestationData> for InternalAttestationData {
    type Error = &'static str;

    fn try_from(value: &AttestationData) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: value.slot,
            index: value.index,
            beacon_block_root: value.beacon_block_root.0,
            source: InternalCheckpoint {
                epoch: value.source.epoch,
                root: value.source.root.0,
            },
            target: InternalCheckpoint {
                epoch: value.target.epoch,
                root: value.target.root.0,
            },
        })
    }
}

pub fn compute_signing_root(hash_tree_root: &Node, domain: &[u8; 32]) -> Result<Vec<u8>> {
    let root = InternalSigningData {
        object_root: *hash_tree_root,
        domain: *domain,
    }
    .hash_tree_root()?;

    Ok(root.as_ref().to_vec())
}
