use super::BeaconBlockHeader;
use anyhow::Result;
use ssz_rs::prelude::*;

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
            parent_root: value.parent_root,
            state_root: value.state_root,
            body_root: value.body_root,
        })
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalForkData {
    pub current_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
struct InternalSigningData {
    pub object_root: Node,
    pub domain: [u8; 32],
}

pub fn compute_signing_root(hash_tree_root: &Node, domain: &[u8; 32]) -> Result<Vec<u8>> {
    let root = InternalSigningData {
        object_root: *hash_tree_root,
        domain: *domain,
    }
    .hash_tree_root()?;

    Ok(root.as_ref().to_vec())
}
