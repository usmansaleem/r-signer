//! Library that exposes various datastructures and ssz hash tree root computation

mod internal;
#[cfg(test)]
mod tests;
pub mod types;

use crate::internal::*;
use crate::types::*;
use anyhow::Result;
use specs::Spec;
use ssz_rs::Merkleized;

pub struct SigningRootUtil<'a> {
    spec: &'a Spec,
}

impl<'a> SigningRootUtil<'a> {
    pub fn new(spec: &'a Spec) -> Self {
        SigningRootUtil { spec }
    }

    pub fn signing_root_for_sign_block_header(
        &self,
        block_header: &BeaconBlockHeader,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        //TODO Move these constants
        let beacon_proposer: [u8; 4] = [0, 0, 0, 0];
        let epoch = self.spec.compute_epoch_at_slot(block_header.slot);

        let domain = Self::get_domain(fork_info, &beacon_proposer, epoch)?;

        let hash_tree_root = InternalBeaconBlockHeader::try_from(block_header)
            .unwrap()
            .hash_tree_root()?;

        let result_vec = internal::compute_signing_root(&hash_tree_root, &domain)?;
        Ok(Hash256::from_slice(&result_vec))
    }

    pub fn signing_root_for_sign_attestation_data(
        &self,
        attestation_data: &AttestationData,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        // TODO: Move as constant
        let domain_beacon_attester: [u8; 4] = hex_literal::hex!("01000000");

        let domain = Self::get_domain(
            fork_info,
            &domain_beacon_attester,
            attestation_data.target.epoch,
        )?;

        let hash_tree_root = InternalAttestationData::try_from(attestation_data)
            .unwrap() // will not panic
            .hash_tree_root()?;

        let result_vec = internal::compute_signing_root(&hash_tree_root, &domain)?;
        Ok(Hash256::from_slice(&result_vec))
    }

    pub fn signing_root_for_sign_aggegation_slot(
        &self,
        aggregation_slot: &AggregationSlot,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        // TODO: Move as constant
        let domain_selection_proof: [u8; 4] = hex_literal::hex!("05000000");
        let epoch = self.spec.compute_epoch_at_slot(aggregation_slot.slot);
        let domain = Self::get_domain(fork_info, &domain_selection_proof, epoch)?;
        let hash_tree_root = SszU64(aggregation_slot.slot).hash_tree_root()?;

        let result_vec = internal::compute_signing_root(&hash_tree_root, &domain)?;
        Ok(Hash256::from_slice(&result_vec))
    }

    pub fn signing_root_for_randao_reveal(
        &self,
        randao_reveal: &RandaoReveal,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        //TODO: Move as constant
        let domain_randao: [u8; 4] = hex_literal::hex!("02000000");

        let domain = Self::get_domain(fork_info, &domain_randao, randao_reveal.epoch)?;

        let hash_tree_root = SszU64(randao_reveal.epoch).hash_tree_root()?;

        let result_vec = internal::compute_signing_root(&hash_tree_root, &domain)?;
        Ok(Hash256::from_slice(&result_vec))
    }

    pub fn signing_root_for_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        //TODO: Move as constant
        let domain_voluntary_exit: [u8; 4] = hex_literal::hex!("04000000");

        let domain = Self::get_domain(fork_info, &domain_voluntary_exit, voluntary_exit.epoch)?;

        let hash_tree_root = InternalVoluntaryExit::try_from(voluntary_exit)
            .unwrap()
            .hash_tree_root()?;

        let result_vec = internal::compute_signing_root(&hash_tree_root, &domain)?;
        Ok(Hash256::from_slice(&result_vec))
    }

    fn get_domain(fork_info: &ForkInfo, domain_type: &[u8; 4], epoch: u64) -> Result<Hash256> {
        let fork_version = if epoch < fork_info.fork.epoch {
            &fork_info.fork.previous_version
        } else {
            &fork_info.fork.current_version
        };

        Self::compute_domain(
            domain_type,
            fork_version,
            &fork_info.genesis_validators_root,
        )
    }

    fn compute_domain(
        domain_type: &[u8; 4],
        fork_version: &[u8; 4],
        genesis_validators_root: &Hash256,
    ) -> Result<Hash256> {
        let mut fork_data = InternalForkData {
            current_version: *fork_version,
            genesis_validators_root: genesis_validators_root.0,
        };
        let fork_data_root = fork_data.hash_tree_root()?;
        let domain_root = [&domain_type[..], &fork_data_root.as_ref()[..28]].concat();
        Ok(Hash256::from_slice(&domain_root))
    }
}
