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

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let signing_root = signing_root_util.signing_root_for_sign_block_header(&block_header, &fork_info)
        .unwrap()
        .0;
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

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);

    let expected_signing_root =
        hex!("548c9a015f4c96cb8b1ddbbdfca85846f85bf9f344a434c140f378cdfb5341f0");
    let signing_root = signing_root_util.signing_root_for_sign_attestation_data(&attestation_data, &fork_info)
        .unwrap()
        .0;

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
    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let expected_signing_root =
        hex!("1fb90dd6e8b2670e6949347bc4eaacd37f9b6cc6e42c559973e362c800e853b9");
    let signing_root = signing_root_util.signing_root_for_sign_aggegation_slot(&aggregation_slot, &fork_info)
        .unwrap()
        .0;

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_randao_reveal_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let randao = RandaoReveal { epoch: 3 };
    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let expected_signing_root =
        hex!("3d047c51a8b03630781dc4c5519c17f7de87174246ff2deed0f195c6c775f91e");
    let signing_root = signing_root_util.signing_root_for_randao_reveal(&randao, &fork_info)
        .unwrap()
        .0;

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_voluntary_exit_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let voluntary_exit = VoluntaryExit {
        epoch: 119,
        validator_index: 0,
    };

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);

    let expected_signing_root =
        hex!("38e9f1cfe7926ce5366b633b7fc7113129025737394002d2637faaeefc56913d");
    let signing_root = signing_root_util.signing_root_for_voluntary_exit(&voluntary_exit, &fork_info)
        .unwrap()
        .0;

    assert_eq!(signing_root, expected_signing_root);
}

/*
{
  "type" : "AGGREGATE_AND_PROOF",
  "signingRoot" : "0x8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
  "fork_info" : {
    "fork" : {
      "previous_version" : "0x00000001",
      "current_version" : "0x00000001",
      "epoch" : "1"
    },
    "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
  },
  "aggregate_and_proof" : {
    "aggregator_index" : "1",
    "aggregate" : {
      "aggregation_bits" : "0x00000101",
      "data" : {
        "slot" : "0",
        "index" : "0",
        "beacon_block_root" : "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
        "source" : {
          "epoch" : "0",
          "root" : "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "target" : {
          "epoch" : "0",
          "root" : "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
        }
      },
      "signature" : "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
    },
    "selection_proof" : "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
  }
}
*/
#[test]
fn signing_root_for_aggregate_and_proof_is_calculated() {}

