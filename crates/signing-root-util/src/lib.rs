//! Library that exposes various datastructures and ssz hash tree root computation
// / TODO: determine slots_per_epochs from spec config (or --network flag) slots_per_epochs: u64 = 32;

mod internal;
#[cfg(test)]
mod tests;
pub mod types;

use crate::internal::*;
use crate::types::*;
use anyhow::Result;
use ssz_rs::Merkleized;

pub fn signing_root_for_sign_block_header(
    block_header: &BeaconBlockHeader,
    fork_info: &ForkInfo,
) -> Result<Bytes32> {
    //TODO Move these constants
    let beacon_proposer: Bytes4 = Bytes4([0, 0, 0, 0]);

    let domain = get_domain(
        fork_info,
        &beacon_proposer,
        compute_epoch_at_slot(block_header.slot),
    )?;

    let hash_tree_root = InternalBeaconBlockHeader::try_from(block_header)
        .unwrap()
        .hash_tree_root()?;

    let result_vec = internal::compute_signing_root(&hash_tree_root, &domain.0)?;
    let result: Bytes32 = Bytes32(
        result_vec
            .try_into()
            .map_err(|_| SigningRootError::VectorConversionError)?,
    );
    Ok(result)
}

pub fn signing_root_for_sign_attestation_data(
    attestation_data: &AttestationData,
    fork_info: &ForkInfo,
) -> Result<Bytes32> {
    // TODO: Move as constant
    let domain_beacon_attester: Bytes4 = Bytes4(hex_literal::hex!("01000000"));

    let domain = get_domain(
        fork_info,
        &domain_beacon_attester,
        attestation_data.target.epoch,
    )?;

    let hash_tree_root = InternalAttestationData::try_from(attestation_data)
        .unwrap() // will not panic
        .hash_tree_root()?;

    let result_vec = internal::compute_signing_root(&hash_tree_root, &domain.0)?;
    let result: Bytes32 = Bytes32(
        result_vec
            .try_into()
            .map_err(|_| SigningRootError::VectorConversionError)?,
    );
    Ok(result)
}

pub fn signing_root_for_sign_aggegation_slot(
    aggregation_slot: &AggregationSlot,
    fork_info: &ForkInfo,
) -> Result<Bytes32> {
    // TODO: Move as constant
    let domain_selection_proof: Bytes4 = Bytes4(hex_literal::hex!("05000000"));

    let domain = get_domain(
        fork_info,
        &domain_selection_proof,
        compute_epoch_at_slot(aggregation_slot.slot),
    )?;
    let hash_tree_root = SszU64(aggregation_slot.slot).hash_tree_root()?;

    let result_vec = internal::compute_signing_root(&hash_tree_root, &domain.0)?;
    let result: Bytes32 = Bytes32(
        result_vec
            .try_into()
            .map_err(|_| SigningRootError::VectorConversionError)?,
    );
    Ok(result)
}

pub fn signing_root_for_randao_reveal(
    randao_reveal: &RandaoReveal,
    fork_info: &ForkInfo,
) -> Result<Bytes32> {
    //TODO: Move as constant
    let domain_randao: Bytes4 = Bytes4(hex_literal::hex!("02000000"));

    let domain = get_domain(fork_info, &domain_randao, randao_reveal.epoch)?;

    let hash_tree_root = SszU64(randao_reveal.epoch).hash_tree_root()?;

    let result_vec = internal::compute_signing_root(&hash_tree_root, &domain.0)?;
    let result: Bytes32 = Bytes32(
        result_vec
            .try_into()
            .map_err(|_| SigningRootError::VectorConversionError)?,
    );
    Ok(result)
}

pub fn signing_root_for_voluntary_exit(
    voluntary_exit: &VoluntaryExit,
    fork_info: &ForkInfo,
) -> Result<Bytes32> {
    //TODO: Move as constant
    let domain_voluntary_exit: Bytes4 = Bytes4(hex_literal::hex!("04000000"));

    let domain = get_domain(fork_info, &domain_voluntary_exit, voluntary_exit.epoch)?;

    let hash_tree_root = InternalVoluntaryExit::try_from(voluntary_exit)
        .unwrap()
        .hash_tree_root()?;

    let result_vec = internal::compute_signing_root(&hash_tree_root, &domain.0)?;
    let result: Bytes32 = Bytes32(
        result_vec
            .try_into()
            .map_err(|_| SigningRootError::VectorConversionError)?,
    );
    Ok(result)
}

// TODO: This will be removed in near future ... this needs to be derived from network spec
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

    compute_domain(
        domain_type,
        fork_version,
        &fork_info.genesis_validators_root,
    )
}

fn compute_domain(
    domain_type: &Bytes4,
    fork_version: &Bytes4,
    genesis_validators_root: &Bytes32,
) -> Result<Bytes32> {
    let mut fork_data = InternalForkData {
        current_version: fork_version.0,
        genesis_validators_root: genesis_validators_root.0,
    };
    let fork_data_root = fork_data.hash_tree_root()?;
    let domain_root = [&domain_type.0[..], &fork_data_root.as_ref()[..28]].concat();

    let result: Bytes32 = Bytes32(
        domain_root
            .try_into()
            .map_err(|_| SigningRootError::VectorConversionError)?,
    );
    Ok(result)
}
