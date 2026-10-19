# flaga_solver

A constraint solver over the static schema that
[`big-bad-bool`](https://crates.io/crates/big-bad-bool) generates for a
`#[bitpack(storage = ...)]` struct.

It answers two questions:

- **Is this raw word valid?** If not, which field, value or bit broke which rule.
- **Is this request authorized?** Given a required word and a policy of an allow
  word and a deny word, every required bit must be allowed and none denied.
  Deny wins. Every refusal names the field, or the flag inside the field.

## The one rule

Nothing is invented. Every rule the solver checks comes from a constant that
`#[bitpack]` already generates:

| Constant     | What the solver does with it                                   |
|--------------|----------------------------------------------------------------|
| `FIELDS`     | layout: any bit outside every field is refused                 |
| `LABELS`     | names values in reasons; resolves relation labels to values    |
| `RANGES`     | a value inside a `Reserved` or `Invalid` range is refused      |
| `FLAGS`      | names single bits in reasons (`flag \`flags\`.cold`)          |
| `RELATIONS`  | `Requires` and `Conflicts` between labels                      |
| `DEPRECATED` | a deprecated value is reported (warning grade)                 |

In a field that has `FLAGS` entries, a label holds when all of its bits are
set. In any other field, a label holds when the value equals it.

## Example

```rust
use big_bad_bool::bitpack;
use flaga_solver::{authorize, check, schema_of, Policy};

#[bitpack(storage = u16)]
pub struct Job16 {
    #[bits(3)] #[labels(signal = 0, timer = 1)] #[requires(timer => profile.inline_queue)]
    reason: u16,
    #[bits(2)] #[labels(pooled = 0, inline_queue = 1)] profile: u16,
    #[bits(2)] #[flags(hot = 0, cold = 1)] flags: u16,
}

let schema = schema_of!(Job16);
let v = check(&schema, Job16::new(1, 0, 0).raw() as u128);
assert_eq!(v.to_string(), "`reason`=timer requires `profile`=inline_queue");
let (hot, cold) = (1u128 << 5, 1u128 << 6);
let v = authorize(&schema, cold, &Policy::new(hot | cold, cold));
assert_eq!(v.to_string(), "flag `flags`.cold denied by policy");
```

`Verdict::is_ok()` is true when nothing refused;
`Verdict::is_ok_ignoring_deprecated()` lets deprecated values through.

## How it relates to the other crates

- `big-bad-bool` owns the layout: the bit math and the schema constants.
- `flaga` manages flags at runtime: named flags, a flag manager, persistence and
  triggers.
- `flaga_solver` reads a `big-bad-bool` schema and checks words against it and
  against allow/deny policy words. It does not depend on `flaga`.

`flaga` exposes this as its optional `solver` feature from 0.3.1.

The library is `#![no_std]` with `alloc`. Its one dependency is
`big-bad-bool-core` with default features off, so it builds without `std`
(checked on `thumbv7em-none-eabihf`). `big-bad-bool` is only a dev-dependency,
for the derive in the tests.

## Tests

`cargo test` runs:

- every rule, with positive and negative cases and the exact reason text, on a
  schema modelled on `ComplexContract32` from `big-bad-bool-test-suite`;
- an exhaustive sweep of all 65,536 words of a `u16` schema against a
  hand-written oracle;
- `authorize` cases: allowed, denied over allowed, missing, malformed;
- the crate-level doctest.

## Releasing

Bump `version` in Cargo.toml, add a dated `## <version> (YYYY-MM-DD)` entry to CHANGELOG.md, and push to
`main`. CI (.github/workflows/ci.yml) runs the tests and clippy, then publishes that version to crates.io.

## License

MIT OR Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
