//! Every `check` rule on a schema that uses every big-bad-bool attribute.

mod common;

use common::{word, Contract32};
use flaga_solver::{check, schema_of, BitFieldSpec, Rule, Verdict};

fn verdict(raw: u128) -> Verdict {
    check(&schema_of!(Contract32), raw)
}

fn texts(v: &Verdict) -> Vec<String> {
    v.refusals.iter().map(ToString::to_string).collect()
}

fn rules(v: &Verdict) -> Vec<Rule> {
    v.refusals.iter().map(|r| r.rule).collect()
}

#[test]
fn schema_of_reads_every_table() {
    let s = schema_of!(Contract32);
    assert_eq!(s.fields.len(), 4);
    assert_eq!(s.labels.len(), 15);
    assert_eq!(s.ranges.len(), 5);
    assert_eq!(s.flags.len(), 4);
    assert_eq!(s.relations.len(), 2);
    assert_eq!(s.deprecated.len(), 2);
    assert_eq!(s.layout_mask(), u128::from(Contract32::RAW_MASK));
}

#[test]
fn default_word_is_ok() {
    let s = schema_of!(Contract32);
    let raw = s.fields.iter().fold(0u128, |acc, f: &BitFieldSpec| {
        acc | (f.default.unwrap_or(0) << f.shift)
    });
    assert_eq!(raw, word(1, 0, 0, 0));
    let v = check(&s, raw);
    assert!(v.is_ok(), "{v}");
    assert_eq!(v.to_string(), "ok");
    assert!(v.first().is_none());
}

#[test]
fn layout() {
    let v = verdict(word(1, 0, 0, 0) | 1 << 17);
    assert_eq!(rules(&v), [Rule::Layout]);
    assert_eq!(texts(&v), ["bit 17 is outside every field of the layout"]);
    assert_eq!(v.first().unwrap().bit, Some(17));
    assert_eq!(v.first().unwrap().field, "");

    let v = verdict(word(1, 0, 0, 0) | 1 << 17 | 1 << 100);
    assert_eq!(rules(&v), [Rule::Layout, Rule::Layout]);
    assert!(verdict(word(2, 2, 2, 0b1_0011)).is_ok());
}

#[test]
fn reserved() {
    assert_eq!(
        texts(&verdict(word(0, 0, 0, 0))),
        ["field `domain` = 0 (reserved) is reserved"]
    );
    assert_eq!(
        texts(&verdict(word(29, 0, 0, 0))),
        ["field `domain` = 29 is reserved"]
    );
    assert_eq!(
        texts(&verdict(word(1, 0, 7, 0))),
        ["field `profile` = 7 is reserved"]
    );
    let v = verdict(word(28, 0, 0, 0));
    assert!(!v.is_ok());
    assert!(!v.is_ok_ignoring_deprecated());
    assert!(verdict(word(27, 0, 5, 0)).is_ok());
}

#[test]
fn invalid() {
    let v = verdict(word(31, 0, 0, 0));
    assert_eq!(rules(&v), [Rule::Invalid]);
    assert_eq!(texts(&v), ["field `domain` = 31 is invalid"]);
    assert_eq!(
        texts(&verdict(word(1, 15, 0, 0))),
        ["field `reason` = 15 is invalid"]
    );
    assert!(verdict(word(1, 14, 0, 0)).is_ok());
}

#[test]
fn deprecated() {
    let v = verdict(word(3, 0, 0, 0));
    assert_eq!(texts(&v), ["field `domain` = 3 (old_domain) is deprecated"]);
    assert!(!v.is_ok());
    assert!(v.is_ok_ignoring_deprecated());

    let v = verdict(word(4, 0, 0, 0));
    assert_eq!(texts(&v), ["field `domain` = 4 is deprecated"]);
    assert_eq!(v.first().unwrap().label, None);

    let v = verdict(word(3, 15, 0, 0));
    assert!(!v.is_ok_ignoring_deprecated());
    assert!(verdict(word(5, 0, 0, 0)).is_ok());
}

#[test]
fn requires() {
    let v = verdict(word(1, 1, 0, 0));
    assert_eq!(rules(&v), [Rule::Requires]);
    assert_eq!(
        texts(&v),
        ["`reason`=timer requires `profile`=inline_queue"]
    );
    let r = v.first().unwrap();
    assert_eq!((r.field, r.value, r.label), ("reason", 1, Some("timer")));
    assert_eq!(
        (r.other_field, r.other_label),
        (Some("profile"), Some("inline_queue"))
    );

    assert_eq!(texts(&verdict(word(1, 1, 2, 0))).len(), 1);
    assert!(verdict(word(1, 1, 1, 0)).is_ok());
    assert!(verdict(word(1, 2, 0, 0)).is_ok());
}

#[test]
fn conflicts() {
    let v = verdict(word(1, 0, 0, 0b1100));
    assert_eq!(rules(&v), [Rule::Conflicts]);
    assert_eq!(
        texts(&v),
        ["`flags`=optimistic conflicts with `flags`=replicated"]
    );
    assert_eq!(rules(&verdict(word(1, 0, 0, 0b1_1111))), [Rule::Conflicts]);
    assert!(verdict(word(1, 0, 0, 0b0100)).is_ok());
    assert!(verdict(word(1, 0, 0, 0b1011)).is_ok());
}

#[test]
fn several_refusals_join() {
    let v = verdict(word(31, 1, 7, 0b1100) | 1 << 30);
    assert_eq!(
        rules(&v),
        [
            Rule::Layout,
            Rule::Invalid,
            Rule::Reserved,
            Rule::Requires,
            Rule::Conflicts
        ]
    );
    assert_eq!(
        v.to_string(),
        "bit 30 is outside every field of the layout; field `domain` = 31 is invalid; \
         field `profile` = 7 is reserved; `reason`=timer requires `profile`=inline_queue; \
         `flags`=optimistic conflicts with `flags`=replicated"
    );
}
