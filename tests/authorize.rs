//! `authorize`: allow/deny policy words over the same schema.

mod common;

use common::{word, Contract32};
use flaga_solver::{authorize, schema_of, Policy, Rule, Verdict};

const HOT: u128 = 1 << 12;
const COLD: u128 = 1 << 13;
const UNNAMED: u128 = 1 << 16;

fn run(required: u128, policy: Policy) -> Verdict {
    authorize(&schema_of!(Contract32), required, &policy)
}

fn all() -> u128 {
    u128::from(Contract32::RAW_MASK)
}

#[test]
fn flag_bits_are_where_the_schema_says() {
    assert_eq!(word(0, 0, 0, 0b01), HOT);
    assert_eq!(word(0, 0, 0, 0b10), COLD);
    assert_eq!(word(0, 0, 0, 0b1_0000), UNNAMED);
}

#[test]
fn subset_of_allow_is_ok() {
    let required = word(1, 0, 0, 0b01);
    let policy = Policy::new(all(), 0);
    let v = run(required, policy);
    assert!(v.is_ok(), "{v}");
    assert!(policy.allows(required));
}

#[test]
fn deny_wins_over_allow() {
    let required = word(1, 0, 0, 0b11);
    let policy = Policy::new(all(), COLD);
    let v = run(required, policy);
    assert_eq!(v.refusals.len(), 1);
    let r = v.first().unwrap();
    assert_eq!(
        (r.rule, r.field, r.label, r.bit),
        (Rule::Denied, "flags", Some("cold"), Some(13))
    );
    assert_eq!(v.to_string(), "flag `flags`.cold denied by policy");
    assert!(!policy.allows(required));
}

#[test]
fn denied_and_not_allowed_is_denied_only() {
    let v = run(word(1, 0, 0, 0b10), Policy::new(all() & !COLD, COLD));
    assert_eq!(v.to_string(), "flag `flags`.cold denied by policy");
}

#[test]
fn missing_from_allow() {
    let required = word(1, 0, 0, 0b01);
    let policy = Policy::new(all() & !HOT, 0);
    let v = run(required, policy);
    assert_eq!(v.refusals.len(), 1);
    assert_eq!(v.first().unwrap().rule, Rule::Missing);
    assert_eq!(v.to_string(), "flag `flags`.hot required but not allowed");
    assert!(!policy.allows(required));
}

#[test]
fn non_flag_bits_are_named_by_field_and_value() {
    let v = run(word(2, 0, 0, 0), Policy::new(all(), 1 << 1));
    assert_eq!(
        v.to_string(),
        "field `domain` = 2 (runtime) denied by policy"
    );
    assert_eq!(v.first().unwrap().bit, None);

    let v = run(word(1, 0, 0, 0b1_0000), Policy::new(all() & !UNNAMED, 0));
    assert_eq!(v.to_string(), "field `flags` = 16 required but not allowed");
}

#[test]
fn malformed_request_is_refused_by_layout() {
    let v = run(word(1, 0, 0, 0b01) | 1 << 20, Policy::new(u128::MAX, 0));
    assert_eq!(v.refusals.len(), 1);
    assert_eq!(v.first().unwrap().rule, Rule::Layout);
    assert_eq!(v.to_string(), "bit 20 is outside every field of the layout");
}

#[test]
fn schema_rules_still_apply_to_requests() {
    let v = run(word(1, 0, 0, 0b1100), Policy::new(all(), 0));
    assert_eq!(
        v.to_string(),
        "`flags`=optimistic conflicts with `flags`=replicated"
    );
}

#[test]
fn every_policy_refusal_names_a_field() {
    let v = run(all(), Policy::new(0, HOT | 1));
    assert!(v.refusals.iter().all(|r| !r.field.is_empty()));
    assert!(v.refusals.iter().any(|r| r.rule == Rule::Denied));
    assert!(v.refusals.iter().any(|r| r.rule == Rule::Missing));
    let text = v.to_string();
    assert!(text.contains("flag `flags`.hot denied by policy"), "{text}");
    assert!(
        text.contains("flag `flags`.replicated required but not allowed"),
        "{text}"
    );
}
