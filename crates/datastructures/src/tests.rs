use super::*;

#[test]
fn compute_domain_works() {
    let domain_type = hex::decode("03000000").unwrap();
    let fork_version = hex::decode("00000001").unwrap();
    let genesis_validators_root =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

    let domain_root =
        compute_domain(&domain_type, &fork_version, &genesis_validators_root).unwrap();
    assert_eq!(
        hex::encode(domain_root),
        "0300000018ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053"
    );
}
