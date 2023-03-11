//! Library that exposes various datastructures and ssz hash tree root computation
// / TODO: determine slots_per_epochs from spec config (or --network flag) slots_per_epochs: u64 = 32;

mod internal;

#[cfg(test)]
mod tests;

use crate::internal::{InternalAttestationData, InternalBeaconBlockHeader, InternalForkData};
use anyhow::Result;
use serde_aux::prelude::deserialize_number_from_string;
use serde_hex::{SerHex, StrictPfx};
use ssz_rs::Merkleized;
use thiserror::Error;

pub type Bytes4 = [u8; 4];
pub type Bytes32 = [u8; 32];

#[derive(Error, Debug)]
enum SigningRootError {
    #[error("Unexpected Error in converting vector to array")]
    VectorConversionError,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlockHeader {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub slot: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub proposer_index: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub parent_root: Bytes32,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub state_root: Bytes32,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub body_root: Bytes32,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Fork {
    #[serde(with = "SerHex::<StrictPfx>")]
    pub previous_version: Bytes4,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub current_version: Bytes4,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub epoch: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForkInfo {
    pub fork: Fork,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub genesis_validators_root: Bytes32,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestationData {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub slot: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub index: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub beacon_block_root: Bytes32,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub epoch: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    pub root: Bytes32,
}

pub fn signing_root_for_sign_block_header(
    block_header: &BeaconBlockHeader,
    fork_info: &ForkInfo,
) -> Result<Bytes32> {
    let mut internal_block_header = InternalBeaconBlockHeader::try_from(block_header).unwrap();
    let block_header_root = internal_block_header.hash_tree_root()?;
    let domain = get_domain_sign_block(block_header.slot, fork_info)?;

    let result_vec = internal::compute_signing_root(&block_header_root, &domain)?;
    let result: Bytes32 = result_vec
        .try_into()
        .map_err(|_| SigningRootError::VectorConversionError)?;
    Ok(result)
}

pub fn signing_root_for_sign_attestation_data(
    attestation_data: &AttestationData,
    fork_info: &ForkInfo,
) -> Result<Bytes32> {
    // TODO: Move as constant
    let domain_beacon_attester: Bytes4 = hex_literal::hex!("01000000");

    let domain = get_domain(
        fork_info,
        &domain_beacon_attester,
        attestation_data.target.epoch,
    )?;

    let hash_tree_root = InternalAttestationData::try_from(attestation_data)
        .unwrap() // will not panic
        .hash_tree_root()?;

    let result_vec = internal::compute_signing_root(&hash_tree_root, &domain)?;
    let result: Bytes32 = result_vec
        .try_into()
        .map_err(|_| SigningRootError::VectorConversionError)?;
    Ok(result)
}

fn get_domain_sign_block(slot: u64, fork_info: &ForkInfo) -> Result<Bytes32> {
    //TODO Move these constants
    let beacon_proposer: Bytes4 = [0, 0, 0, 0];

    get_domain(fork_info, &beacon_proposer, compute_epoch_at_slot(slot))
}

fn compute_epoch_at_slot(slot: u64) -> u64 {
    // TODO: determine slots_per_epocs from spec configs
    let slots_per_epochs: u64 = 32;
    slot / slots_per_epochs
}

fn get_domain(fork_info: &ForkInfo, domain_type: &Bytes4, epoch: u64) -> Result<Bytes32> {
    let fork_version: &Bytes4 = if epoch < fork_info.fork.epoch {
        &fork_info.fork.previous_version
    } else {
        &fork_info.fork.current_version
    };

    let domain_root = compute_domain(
        domain_type,
        fork_version,
        &fork_info.genesis_validators_root,
    )?;
    let result: Bytes32 = domain_root
        .try_into()
        .map_err(|_| SigningRootError::VectorConversionError)?;
    Ok(result)
}

fn compute_domain(
    domain_type: &Bytes4,
    fork_version: &Bytes4,
    genesis_validators_root: &Bytes32,
) -> Result<Vec<u8>> {
    let mut fork_data = InternalForkData {
        current_version: *fork_version,
        genesis_validators_root: *genesis_validators_root,
    };
    let fork_data_root = fork_data.hash_tree_root()?;
    Ok([domain_type, &fork_data_root.as_ref()[..28]].concat())
}
