use super::*;

#[test]
fn minimal_specs_works() {
    let spec = Spec::minimal().unwrap();
    println!("{:?}", spec);
}

#[test]
fn mainnet_specs_works() {
    let spec = Spec::mainnet().unwrap();
    println!("{:?}", spec);
}
