//! Exhaustive sweep of a u16 schema against a hand-written oracle.

use big_bad_bool::bitpack;
use flaga_solver::{check, schema_of, Rule};

#[bitpack(storage = u16)]
pub struct Tiny16 {
    #[bits(3)]
    #[labels(off = 0, low = 1, high = 2, legacy = 3)]
    #[reserved(5..=6)]
    #[invalid(7)]
    #[deprecated(legacy, since = "0.1.0", note = "Use low.")]
    #[requires(high => mode.armed)]
    level: u16,

    #[bits(2)]
    #[labels(idle = 0, armed = 1)]
    #[invalid(3)]
    mode: u16,

    #[bits(4)]
    #[labels(none = 0, a = 1, b = 2, c = 4)]
    #[flags(a = 0, b = 1, c = 2, d = 3)]
    #[conflicts(a, b, c)]
    #[requires(c => mode.armed)]
    caps: u16,

    #[bits(5)]
    #[reserved(16..=31)]
    tail: u16,
}

type Key = (Rule, &'static str, Option<&'static str>);

/// Written from the declaration above by hand; uses no schema constant.
fn oracle(raw: u32) -> Vec<Key> {
    let mut out = Vec::new();
    for bit in 14..16 {
        if raw >> bit & 1 == 1 {
            out.push((Rule::Layout, "", None));
        }
    }
    let level = raw & 0b111;
    let mode = raw >> 3 & 0b11;
    let caps = raw >> 5 & 0b1111;
    let tail = raw >> 9 & 0b1_1111;
    if (5..=6).contains(&level) {
        out.push((Rule::Reserved, "level", None));
    }
    if level == 7 {
        out.push((Rule::Invalid, "level", None));
    }
    if level == 3 {
        out.push((Rule::Deprecated, "level", None));
    }
    if mode == 3 {
        out.push((Rule::Invalid, "mode", None));
    }
    if tail >= 16 {
        out.push((Rule::Reserved, "tail", None));
    }
    if level == 2 && mode != 1 {
        out.push((Rule::Requires, "level", Some("armed")));
    }
    let (a, b, c) = (caps & 1 != 0, caps & 2 != 0, caps & 4 != 0);
    if a && b {
        out.push((Rule::Conflicts, "caps", Some("b")));
    }
    if a && c {
        out.push((Rule::Conflicts, "caps", Some("c")));
    }
    if b && c {
        out.push((Rule::Conflicts, "caps", Some("c")));
    }
    if c && mode != 1 {
        out.push((Rule::Requires, "caps", Some("armed")));
    }
    out.sort();
    out
}

#[test]
fn every_u16_matches_the_oracle() {
    let schema = schema_of!(Tiny16);
    let (mut ok, mut ok_ignoring_deprecated, mut refusals, mut oracle_refusals) = (0, 0, 0, 0);
    let mut per_rule = [0u32; 8];
    for raw in 0..=u32::from(u16::MAX) {
        let verdict = check(&schema, u128::from(raw));
        let mut got: Vec<Key> = verdict
            .refusals
            .iter()
            .map(|r| (r.rule, r.field, r.other_label))
            .collect();
        got.sort();
        let want = oracle(raw);
        assert_eq!(got, want, "raw {raw:#06x}: {verdict}");
        ok += u32::from(verdict.is_ok());
        ok_ignoring_deprecated += u32::from(verdict.is_ok_ignoring_deprecated());
        refusals += got.len();
        oracle_refusals += want.len();
        for r in &verdict.refusals {
            per_rule[r.rule as usize] += 1;
        }
    }
    println!("ok={ok} ok_ignoring_deprecated={ok_ignoring_deprecated} refusals={refusals} per_rule={per_rule:?}");
    assert_eq!(refusals, oracle_refusals);
    // Counted by hand: 3 plain levels x 20 (mode, caps) pairs + high x 8, times 16 tails.
    assert_eq!(ok, 1088);
    // Plus legacy x 20 x 16.
    assert_eq!(ok_ignoring_deprecated, 1408);
}
