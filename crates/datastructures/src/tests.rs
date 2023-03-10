use super::*;
use hex_literal::hex;

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
