use super::*;

#[test]
fn normalize_works_with_space() {
    let input = String::from("test test");
    let result = normalize_password(input);
    assert_eq!(result, String::from("test test"));
}

#[test]
fn normalize_strips_c0_control_chars() {
    let input = String::from("test\u{001F}test");
    let result = normalize_password(input);
    assert_eq!(result, String::from("testtest"));
}

#[test]
fn normalize_strips_c1_control_chars() {
    let input = String::from("test\u{0080}\u{0081}\u{009F}test");
    let result = normalize_password(input);
    assert_eq!(result, String::from("testtest"));
}

#[test]
fn normalize_strips_delete_control_chars() {
    let input = String::from("test\u{007F}test");
    let result = normalize_password(input);
    assert_eq!(result, String::from("testtest"));
}

#[test]
fn normalize_works_with_non_control_char() {
    let input = String::from("test\u{0020}test");
    let result = normalize_password(input);
    assert_eq!(result, String::from("test\u{0020}test"));
}
