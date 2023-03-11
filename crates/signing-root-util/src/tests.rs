use super::*;
use hex_literal::hex;

#[test]
fn signing_root_for_sign_block_header_is_calculated() {
    let fork_info_json = r#"{
            "fork":{
                "previous_version":"0x00000001",
                "current_version":"0x00000001",
                "epoch":"1"
             },
            "genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
           }"#;
    let block_header_json = r#"{
        "slot":"0",
        "proposer_index":"4666673844721362956",
        "parent_root":"0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
        "state_root":"0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
        "body_root":"0xe74b0fc13f19ae2077403afa03fdc155484f22d05d93eb084473951bb3a8d1ae"
    }"#;
    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let block_header: BeaconBlockHeader = serde_json::from_str(block_header_json).unwrap();

    let signing_root = signing_root_for_sign_block_header(&block_header, &fork_info).unwrap();
    assert_eq!(
        signing_root,
        hex!("26d0ee0b6c2261cd6010112a024de4f3d2e1e9844d11d60b057fac344c745464")
    );
}

#[test]
fn signing_root_for_sign_attestation_data_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;
    let attestation_data_json = r#"{
        "slot" : "32",
        "index" : "0",
        "beacon_block_root" : "0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
        "source" : {
          "epoch" : "0",
          "root" : "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "target" : {
          "epoch" : "0",
          "root" : "0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89"
        }
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let attestation_data: AttestationData = serde_json::from_str(attestation_data_json).unwrap();

    let expected_signing_root =
        hex!("548c9a015f4c96cb8b1ddbbdfca85846f85bf9f344a434c140f378cdfb5341f0");
    let signing_root =
        signing_root_for_sign_attestation_data(&attestation_data, &fork_info).unwrap();

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_sign_aggegation_slot_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let aggregation_slot = AggregationSlot { slot: 119 };

    let expected_signing_root =
        hex!("1fb90dd6e8b2670e6949347bc4eaacd37f9b6cc6e42c559973e362c800e853b9");
    let signing_root =
        signing_root_for_sign_aggegation_slot(&aggregation_slot, &fork_info).unwrap();

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn compute_domain_works() {
    let domain_type = hex!("03000000");
    let fork_version = hex!("00000001");
    let genesis_validators_root =
        hex!("0000000000000000000000000000000000000000000000000000000000000000");

    let domain_root =
        compute_domain(&domain_type, &fork_version, &genesis_validators_root).unwrap();
    assert_eq!(
        domain_root,
        hex!("0300000018ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053")
    );
}
