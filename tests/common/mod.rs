//! Shared test schema, modelled on `ComplexContract32` from
//! `big-bad-bool-test-suite` 0.1.0.

use big_bad_bool::bitpack;

#[bitpack(storage = u32, version = 7)]
pub struct Contract32 {
    #[bits(5)]
    #[describe("Top-level contract domain.")]
    #[labels(reserved = 0, builder = 1, runtime = 2, old_domain = 3)]
    #[reserved(0, 28..=30)]
    #[invalid(31)]
    #[default(1)]
    #[deprecated(old_domain, since = "0.1.0", note = "Use builder or runtime instead.")]
    #[deprecated(4, since = "0.1.0", note = "Unnamed legacy domain.")]
    #[dispatch(key)]
    pub domain: u32,

    #[bits(4)]
    #[labels(signal = 0, timer = 1, io = 2)]
    #[requires(timer => profile.inline_queue)]
    #[invalid(15)]
    #[default(0)]
    pub reason: u32,

    #[bits(3)]
    #[labels(pooled = 0, inline_queue = 1, dedicated = 2)]
    #[reserved(6..=7)]
    #[default(0)]
    pub profile: u32,

    #[bits(5)]
    #[labels(none = 0, hot = 1, cold = 2, optimistic = 4, replicated = 8)]
    #[flags(hot = 0, cold = 1, optimistic = 2, replicated = 3)]
    #[conflicts(optimistic, replicated)]
    #[dispatch(flags)]
    pub flags: u32,
}

/// Raw word of a `Contract32` built field by field.
pub fn word(domain: u32, reason: u32, profile: u32, flags: u32) -> u128 {
    u128::from(Contract32::new(domain, reason, profile, flags).raw())
}
