//! Library that exposes various datastructures and ssz hash tree root computation

#[cfg(test)]
mod tests;

use anyhow::{bail, Result};
use ssz_rs::prelude::*;

pub type Bytes4 = [u8; 4];
pub type Bytes32 = [u8; 32];

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
struct ForkData {
    current_version: Vector<u8, 4>,
    genesis_validators_root: Vector<u8, 32>,
}

pub fn compute_domain(
    domain_type: &Vec<u8>,
    fork_version: &Vec<u8>,
    genesis_validators_root: &Vec<u8>,
) -> Result<Vec<u8>> {
    let current_version_vec = match Vector::<u8, 4>::try_from(fork_version.to_vec()) {
        Ok(val) => val,
        Err(_) => bail!("Error creating vector from fork_version"),
    };

    let genesis_root_vec = match Vector::<u8, 32>::try_from(genesis_validators_root.to_vec()) {
        Ok(val) => val,
        Err(_) => bail!("Error creating vector from genesis_validators_root"),
    };

    let mut fork_data = ForkData {
        current_version: current_version_vec,
        genesis_validators_root: genesis_root_vec,
    };
    let fork_data_root = fork_data.hash_tree_root()?;
    Ok([&domain_type[..], &fork_data_root.as_ref()[..28]].concat())
}
