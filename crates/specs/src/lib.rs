//! Consensus presets and specs used by r-signer as defined at
//! https://github.com/ethereum/consensus-specs/tree/dev/specs and
//! https://github.com/ethereum/consensus-specs/tree/dev/presets
//!

#[cfg(test)]
mod tests;

use anyhow::{anyhow, Result};
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use serde::Deserialize;

const PRESETS_MINIMAL: [&str; 5] = [
    include_str!("../presets/minimal/phase0.yaml"),
    include_str!("../presets/minimal/altair.yaml"),
    include_str!("../presets/minimal/bellatrix.yaml"),
    include_str!("../presets/minimal/capella.yaml"),
    include_str!("../presets/minimal/deneb.yaml"),
];

const PRESETS_MAINNET: [&str; 5] = [
    include_str!("../presets/minimal/phase0.yaml"),
    include_str!("../presets/minimal/altair.yaml"),
    include_str!("../presets/minimal/bellatrix.yaml"),
    include_str!("../presets/minimal/capella.yaml"),
    include_str!("../presets/minimal/deneb.yaml"),
];

// predefined configs
const MINIMAL_CONFIG: &str = include_str!("../configs/minimal/config.yaml");
const MAINNET_CONFIG: &str = include_str!("../configs/mainnet/config.yaml");

#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct Spec {
    //../configs/mainnet.yaml
    preset_base: String,
    config_name: String,
    // commenting out fields which are not used for signing root calculation and have difficulty in
    // serde yaml deserialization
    //terminal_total_difficulty: U256,
    //terminal_block_hash: U256, //hex
    //terminal_block_hash_activation_epoch: u64,
    min_genesis_active_validator_count: u64,
    min_genesis_time: u64,
    genesis_fork_version: u32,
    genesis_delay: u64,
    altair_fork_version: u32,
    altair_fork_epoch: u64,
    bellatrix_fork_version: u32,
    bellatrix_fork_epoch: u64,
    capella_fork_version: u32,
    capella_fork_epoch: u64,
    deneb_fork_version: u32,
    deneb_fork_epoch: u64,
    seconds_per_slot: u64,
    seconds_per_eth1_block: u64,
    min_validator_withdrawability_delay: u64,
    shard_committee_period: u64,
    eth1_follow_distance: u64,
    inactivity_score_bias: u64,
    inactivity_score_recovery_rate: u64,
    ejection_balance: u64,
    min_per_epoch_churn_limit: u64,
    churn_limit_quotient: u64,
    proposer_score_boost: u64,
    deposit_chain_id: u64,
    deposit_network_id: u64,
    //deposit_contract_address: Address, //hex

    //../presets/mainnet/phase0.yaml
    max_committees_per_slot: u64,
    target_committee_size: u64,
    max_validators_per_committee: u64,
    shuffle_round_count: u64,
    hysteresis_quotient: u64,
    hysteresis_downward_multiplier: u64,
    hysteresis_upward_multiplier: u64,
    min_deposit_amount: u64,
    max_effective_balance: u64,
    effective_balance_increment: u64,
    min_attestation_inclusion_delay: u64,
    slots_per_epoch: u64,
    min_seed_lookahead: u64,
    max_seed_lookahead: u64,
    epochs_per_eth1_voting_period: u64,
    slots_per_historical_root: u64,
    min_epochs_to_inactivity_penalty: u64,
    epochs_per_historical_vector: u64,
    epochs_per_slashings_vector: u64,
    historical_roots_limit: u64,
    validator_registry_limit: u64,
    base_reward_factor: u64,
    whistleblower_reward_quotient: u64,
    proposer_reward_quotient: u64,
    inactivity_penalty_quotient: u64,
    min_slashing_penalty_quotient: u64,
    proportional_slashing_multiplier: u64,
    max_proposer_slashings: u64,
    max_attester_slashings: u64,
    max_attestations: u64,
    max_deposits: u64,
    max_voluntary_exits: u64,
    //../presets/mainnet/altair.yaml
    inactivity_penalty_quotient_altair: u64,
    min_slashing_penalty_quotient_altair: u64,
    proportional_slashing_multiplier_altair: u64,
    sync_committee_size: u64,
    epochs_per_sync_committee_period: u64,
    min_sync_committee_participants: u64,
    update_timeout: u64,
    //../presets/mainnet/bellatrix.yaml
    inactivity_penalty_quotient_bellatrix: u64,
    min_slashing_penalty_quotient_bellatrix: u64,
    proportional_slashing_multiplier_bellatrix: u64,
    max_bytes_per_transaction: u64,
    max_transactions_per_payload: u64,
    bytes_per_logs_bloom: u64,
    max_extra_data_bytes: u64,
    //../presets/mainnet/capella.yaml
    max_bls_to_execution_changes: u64,
    max_withdrawals_per_payload: u64,
    max_validators_per_withdrawals_sweep: u64,
    // ../presets/mainnet/deneb.yaml
    field_elements_per_blob: u64,
    max_blobs_per_block: u64,
}

impl Spec {
    pub fn mainnet() -> Result<Self> {
        let mut figment = Figment::new();
        for presets in PRESETS_MAINNET {
            figment = figment.merge(Yaml::string(presets));
        }
        figment
            .merge(Yaml::string(MAINNET_CONFIG))
            .extract()
            .map_err(|e| anyhow!("Error extracting mainnet config: {}", e))
    }

    pub fn minimal() -> Result<Self> {
        let mut figment = Figment::new();
        for presets in PRESETS_MINIMAL {
            figment = figment.merge(Yaml::string(presets));
        }
        figment
            .merge(Yaml::string(MINIMAL_CONFIG))
            .extract()
            .map_err(|e| anyhow!("Error extracting minimal config: {}", e))
    }
}
