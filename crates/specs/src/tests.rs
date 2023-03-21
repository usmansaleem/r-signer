use super::*;

#[test]
fn minimal_specs_works() {
    let spec = Spec::new("minimal").unwrap();
    assert_eq!(spec.max_committees_per_slot, 4);
    assert_eq!(spec.config_name, "minimal");
}

#[test]
fn mainnet_specs_works() {
    let spec = Spec::new("mainnet").unwrap();
    assert_eq!(spec.max_committees_per_slot, 64);
    assert_eq!(spec.config_name, "mainnet");
}
