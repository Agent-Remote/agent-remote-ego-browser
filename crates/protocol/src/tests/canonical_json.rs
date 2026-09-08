use serde::Deserialize;

use super::{canonical_json, parse_strict_json, StrictJsonError};

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Example {
    a: u64,
    b: String,
}

#[test]
fn rejects_duplicate_nested_keys() {
    let error = parse_strict_json::<Example>(br#"{"a":1,"b":"x","nested":{"x":1,"x":2}}"#)
        .expect_err("duplicate must fail");
    assert!(matches!(error, StrictJsonError::DuplicateKey(key) if key == "x"));
}

#[test]
fn canonicalizes_object_order() {
    let value: serde_json::Value = serde_json::json!({"z": 1, "a": {"d": 2, "c": 3}});
    assert_eq!(
        canonical_json(&value).unwrap(),
        br#"{"a":{"c":3,"d":2},"z":1}"#
    );
}
