use super::{AggregateAndProof, Attestation, AttestationData, BeaconBlockHeader, VoluntaryExit};
use anyhow::Result;
use bit_vec::BitVec;
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
    type Error = anyhow::Error;

    fn try_from(value: &BeaconBlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: *value.parent_root.as_fixed_bytes(),
            state_root: *value.state_root.as_fixed_bytes(),
            body_root: *value.body_root.as_fixed_bytes(),
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
pub struct InternalVoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}

impl TryFrom<&VoluntaryExit> for InternalVoluntaryExit {
    type Error = anyhow::Error;

    fn try_from(value: &VoluntaryExit) -> Result<Self, Self::Error> {
        Ok(Self {
            epoch: value.epoch,
            validator_index: value.validator_index,
        })
    }
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
    type Error = anyhow::Error;

    fn try_from(value: &AttestationData) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: value.slot,
            index: value.index,
            beacon_block_root: value.beacon_block_root.0,
            source: InternalCheckpoint {
                epoch: value.source.epoch,
                root: *value.source.root.as_fixed_bytes(),
            },
            target: InternalCheckpoint {
                epoch: value.target.epoch,
                root: *value.target.root.as_fixed_bytes(),
            },
        })
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalAttestation {
    pub aggregation_bits: Bitlist<2048>, //the size of bit list is supposed to be maxValidatorsPerCommittee. Mainnet contains 2048
    pub data: InternalAttestationData,
    pub signature: Vector<u8, 96>,
}

impl TryFrom<&Attestation> for InternalAttestation {
    type Error = anyhow::Error;

    fn try_from(value: &Attestation) -> Result<Self, Self::Error> {
        let _bit_vec = BitVec::from_bytes(&value.aggregation_bits);
        let aggregation_bits: Bitlist<2048> = Bitlist::from_iter(_bit_vec);
        let data = InternalAttestationData::try_from(&value.data)?;
        let signature = Vector::<u8, 96>::try_from(value.signature.to_fixed_bytes().to_vec())
            .map_err(|_| anyhow::anyhow!("Error converting signature bytes to ssz Vector"))?;

        Ok(Self {
            aggregation_bits,
            data,
            signature,
        })
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalAggregateAndProof {
    pub aggregator_index: u64,
    pub aggregate: InternalAttestation,
    pub selection_proof: Vector<u8, 96>,
}

impl TryFrom<&AggregateAndProof> for InternalAggregateAndProof {
    type Error = anyhow::Error;

    fn try_from(value: &AggregateAndProof) -> Result<Self, Self::Error> {
        let aggregator_index = value.aggregator_index;
        let aggregate = InternalAttestation::try_from(&value.aggregate)?;
        let selection_proof = Vector::<u8, 96>::try_from(
            value.selection_proof.to_fixed_bytes().to_vec(),
        )
        .map_err(|_| anyhow::anyhow!("Error converting selection_proof bytes to ssz Vector"))?;

        Ok(Self {
            aggregator_index,
            aggregate,
            selection_proof,
        })
    }
}

pub fn compute_signing_root(hash_tree_root: &Node, domain: &crate::Hash256) -> Result<Vec<u8>> {
    let root = InternalSigningData {
        object_root: *hash_tree_root,
        domain: *domain.as_fixed_bytes(),
    }
    .hash_tree_root()?;

    Ok(root.as_ref().to_vec())
}
