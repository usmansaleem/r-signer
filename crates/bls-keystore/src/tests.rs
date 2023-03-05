use super::*;

#[test]
fn normalize_works() {
    let input = String::from("åççèñt");
    let result = normalize_password(input.clone());
    assert_ne!(result, input);
}
