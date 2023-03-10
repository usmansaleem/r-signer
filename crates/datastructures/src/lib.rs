//! Library that exposes various datastructures and ssz hash tree root computation

#[cfg(test)]
mod tests;

use anyhow::Result;
use ssz_rs::prelude::*;

pub type Bytes4 = [u8; 4];
pub type Bytes32 = [u8; 32];

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
struct ForkData {
    current_version: Bytes4,
    genesis_validators_root: Bytes32,
}

pub fn compute_domain(
    domain_type: &Bytes4,
    fork_version: &Bytes4,
    genesis_validators_root: &Bytes32,
) -> Result<Vec<u8>> {
    let mut fork_data = ForkData {
        current_version: *fork_version,
        genesis_validators_root: *genesis_validators_root,
    };
    let fork_data_root = fork_data.hash_tree_root()?;
    Ok([&domain_type[..], &fork_data_root.as_ref()[..28]].concat())
}
