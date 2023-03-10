use super::*;
use hex_literal::hex;
/*
{
"type":"BLOCK_V2",
"signingRoot":"0x26d0ee0b6c2261cd6010112a024de4f3d2e1e9844d11d60b057fac344c745464",
"fork_info":{"fork":{"previous_version":"0x00000001","current_version":"0x00000001","epoch":"1"},
"genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"},
"beacon_block":{
    "version":"BELLATRIX",
    "block_header":{
        "slot":"0",
        "proposer_index":"4666673844721362956",
        "parent_root":"0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
        "state_root":"0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
        "body_root":"0xe74b0fc13f19ae2077403afa03fdc155484f22d05d93eb084473951bb3a8d1ae"
    }
}
}
*/

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
