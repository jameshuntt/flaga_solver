#![no_std]
#![forbid(unsafe_code)]
//! Constraint solver over the static schema that `big-bad-bool` generates for a
//! `#[bitpack(storage = ...)]` struct.
//!
//! Every rule checked here comes from a constant the derive already emits:
//! `FIELDS`, `LABELS`, `RANGES`, `FLAGS`, `RELATIONS` and `DEPRECATED`. Nothing
//! is invented. [`check`] says whether a raw word is valid under those rules and
//! names the field, value and rule behind every refusal. [`authorize`] checks a
//! required word against an allow word and a deny word; deny wins.
//!
//! ```
//! use big_bad_bool::bitpack;
//! use flaga_solver::{authorize, check, schema_of, Policy};
//!
//! #[bitpack(storage = u16)]
//! pub struct Job16 {
//!     #[bits(3)]
//!     #[labels(signal = 0, timer = 1)]
//!     #[requires(timer => profile.inline_queue)]
//!     #[invalid(7)]
//!     reason: u16,
//!     #[bits(2)]
//!     #[labels(pooled = 0, inline_queue = 1)]
//!     profile: u16,
//!     #[bits(2)]
//!     #[flags(hot = 0, cold = 1)]
//!     flags: u16,
//! }
//!
//! let schema = schema_of!(Job16);
//!
//! assert!(check(&schema, Job16::new(1, 1, 0).raw() as u128).is_ok());
//! let verdict = check(&schema, Job16::new(1, 0, 0).raw() as u128);
//! assert_eq!(verdict.to_string(), "`reason`=timer requires `profile`=inline_queue");
//!
//! let hot = Job16::new(0, 0, 0b01).raw() as u128;
//! let cold = Job16::new(0, 0, 0b10).raw() as u128;
//! let policy = Policy::new(hot | cold, cold);
//! assert!(authorize(&schema, hot, &policy).is_ok());
//! assert_eq!(
//!     authorize(&schema, cold, &policy).to_string(),
//!     "flag `flags`.cold denied by policy"
//! );
//! ```

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

pub use big_bad_bool_core::{
    BitFieldSpec, BitFlag, DeprecatedValue, FieldRelation, FieldRelationKind, ValueLabel,
    ValueRange, ValueRangeKind,
};

/// The rule tables of one packed word, borrowed from the constants that
/// `#[bitpack]` generates. Build it with [`schema_of!`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema<'a> {
    /// `FIELDS`: the bit layout.
    pub fields: &'a [BitFieldSpec],
    /// `LABELS`: names for concrete field values.
    pub labels: &'a [ValueLabel],
    /// `RANGES`: reserved and invalid value ranges.
    pub ranges: &'a [ValueRange],
    /// `FLAGS`: named bits inside a field.
    pub flags: &'a [BitFlag],
    /// `RELATIONS`: requires and conflicts between labels.
    pub relations: &'a [FieldRelation],
    /// `DEPRECATED`: deprecated field values.
    pub deprecated: &'a [DeprecatedValue],
}

/// Builds a [`Schema`] from a `#[bitpack]` type's generated constants.
///
/// The constants are inherent on the generated struct, not on the
/// `PackedWord` trait, so a macro reads them by name.
#[macro_export]
macro_rules! schema_of {
    ($t:ty) => {
        $crate::Schema {
            fields: <$t>::FIELDS,
            labels: <$t>::LABELS,
            ranges: <$t>::RANGES,
            flags: <$t>::FLAGS,
            relations: <$t>::RELATIONS,
            deprecated: <$t>::DEPRECATED,
        }
    };
}

impl Schema<'_> {
    /// Union of every field mask: the bits the layout owns.
    #[must_use]
    pub fn layout_mask(&self) -> u128 {
        self.fields.iter().fold(0, |acc, f| acc | f.mask)
    }

    /// Looks up a field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&BitFieldSpec> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// The label `LABELS` gives to `value` in `field`, if any.
    #[must_use]
    pub fn label_for(&self, field: &str, value: u128) -> Option<&'static str> {
        self.labels
            .iter()
            .find(|l| l.field == field && l.value == value)
            .map(|l| l.label)
    }

    /// The value `LABELS` gives to `label` in `field`, if any.
    #[must_use]
    pub fn label_value(&self, field: &str, label: &str) -> Option<u128> {
        self.labels
            .iter()
            .find(|l| l.field == field && l.label == label)
            .map(|l| l.value)
    }

    /// True when `FLAGS` names at least one bit inside `field`, which makes
    /// the field a set of composable bits rather than one exclusive value.
    #[must_use]
    pub fn is_flag_field(&self, field: &str) -> bool {
        self.flags.iter().any(|f| f.field == field)
    }

    /// True when `value` of `field` holds the label value `label_value`.
    ///
    /// In a flag field a label holds when all its bits are set (a zero label
    /// holds only when the field is zero). In any other field it holds on
    /// equality. This is the one place that rule lives.
    #[must_use]
    pub fn holds(&self, field: &str, value: u128, label_value: u128) -> bool {
        if self.is_flag_field(field) && label_value != 0 {
            value & label_value == label_value
        } else {
            value == label_value
        }
    }

    fn value_of(field: &BitFieldSpec, raw: u128) -> u128 {
        (raw & field.mask) >> field.shift
    }

    fn label_holds(&self, field: &str, label: &str, raw: u128) -> bool {
        match (self.field(field), self.label_value(field, label)) {
            (Some(spec), Some(lv)) => self.holds(field, Self::value_of(spec, raw), lv),
            _ => false,
        }
    }
}

/// Which schema rule a refusal comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// A bit is set outside every field in `FIELDS`.
    Layout,
    /// A field value falls in a `RANGES` entry of kind `Reserved`.
    Reserved,
    /// A field value falls in a `RANGES` entry of kind `Invalid`.
    Invalid,
    /// A `RELATIONS` entry of kind `Requires` is not met.
    Requires,
    /// A `RELATIONS` entry of kind `Conflicts` is violated.
    Conflicts,
    /// A field value is listed in `DEPRECATED`. Warning grade, still reported.
    Deprecated,
    /// A required bit is set in the policy's deny word.
    Denied,
    /// A required bit is not set in the policy's allow word.
    Missing,
}

/// One broken rule, named through the schema.
///
/// `field` is empty only for [`Rule::Layout`], whose bit lies outside every
/// field. `bit` is an absolute bit position in the raw word; for
/// [`Rule::Denied`] and [`Rule::Missing`] it is set exactly when the refusal
/// names a `FLAGS` entry, and `label` is then that flag's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Refusal {
    /// The rule that refused.
    pub rule: Rule,
    /// The field the rule is about.
    pub field: &'static str,
    /// The field's value, or the whole raw word for [`Rule::Layout`].
    pub value: u128,
    /// The value's label, the relation's source label, or the flag name.
    pub label: Option<&'static str>,
    /// The other field of a relation.
    pub other_field: Option<&'static str>,
    /// The other label of a relation.
    pub other_label: Option<&'static str>,
    /// Absolute bit position, for layout and flag refusals.
    pub bit: Option<u32>,
}

impl Refusal {
    fn field_value(
        rule: Rule,
        field: &'static str,
        value: u128,
        label: Option<&'static str>,
    ) -> Self {
        Self {
            rule,
            field,
            value,
            label,
            other_field: None,
            other_label: None,
            bit: None,
        }
    }

    fn write_field_value(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "field `{}` = {}", self.field, self.value)?;
        if let Some(label) = self.label {
            write!(f, " ({label})")?;
        }
        Ok(())
    }

    fn write_policy(&self, f: &mut fmt::Formatter<'_>, what: &str) -> fmt::Result {
        if let (Some(_), Some(flag)) = (self.bit, self.label) {
            write!(f, "flag `{}`.{flag} {what}", self.field)
        } else {
            self.write_field_value(f)?;
            write!(f, " {what}")
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let other = (
            self.label.unwrap_or(""),
            self.other_field.unwrap_or(""),
            self.other_label.unwrap_or(""),
        );
        match self.rule {
            Rule::Layout => write!(
                f,
                "bit {} is outside every field of the layout",
                self.bit.unwrap_or(0)
            ),
            Rule::Reserved => {
                self.write_field_value(f)?;
                f.write_str(" is reserved")
            }
            Rule::Invalid => {
                self.write_field_value(f)?;
                f.write_str(" is invalid")
            }
            Rule::Deprecated => {
                self.write_field_value(f)?;
                f.write_str(" is deprecated")
            }
            Rule::Requires => write!(
                f,
                "`{}`={} requires `{}`={}",
                self.field, other.0, other.1, other.2
            ),
            Rule::Conflicts => write!(
                f,
                "`{}`={} conflicts with `{}`={}",
                self.field, other.0, other.1, other.2
            ),
            Rule::Denied => self.write_policy(f, "denied by policy"),
            Rule::Missing => self.write_policy(f, "required but not allowed"),
        }
    }
}

/// Every refusal found for one word. Empty means accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Refusals in the order they were found.
    pub refusals: Vec<Refusal>,
}

impl Verdict {
    /// True when nothing refused.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.refusals.is_empty()
    }

    /// True when every refusal is [`Rule::Deprecated`].
    #[must_use]
    pub fn is_ok_ignoring_deprecated(&self) -> bool {
        self.refusals.iter().all(|r| r.rule == Rule::Deprecated)
    }

    /// The first refusal, if any.
    #[must_use]
    pub fn first(&self) -> Option<&Refusal> {
        self.refusals.first()
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.refusals.is_empty() {
            return f.write_str("ok");
        }
        for (i, refusal) in self.refusals.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{refusal}")?;
        }
        Ok(())
    }
}

/// Checks `raw` against the schema: layout, `RANGES`, `DEPRECATED`, then
/// `RELATIONS`.
#[must_use]
pub fn check(schema: &Schema<'_>, raw: u128) -> Verdict {
    let mut refusals = Vec::new();

    let stray = raw & !schema.layout_mask();
    for bit in (0..u128::BITS).filter(|b| stray >> b & 1 == 1) {
        refusals.push(Refusal {
            bit: Some(bit),
            ..Refusal::field_value(Rule::Layout, "", raw, None)
        });
    }

    for field in schema.fields {
        let value = Schema::value_of(field, raw);
        let label = schema.label_for(field.name, value);
        for range in schema.ranges.iter().filter(|r| r.field == field.name) {
            if range.contains(value) {
                let rule = match range.kind {
                    ValueRangeKind::Reserved => Rule::Reserved,
                    ValueRangeKind::Invalid => Rule::Invalid,
                };
                refusals.push(Refusal::field_value(rule, field.name, value, label));
            }
        }
        for dep in schema.deprecated {
            if dep.field == field.name && dep.value == value {
                let dep_label = if dep.label.is_empty() {
                    label
                } else {
                    Some(dep.label)
                };
                refusals.push(Refusal::field_value(
                    Rule::Deprecated,
                    field.name,
                    value,
                    dep_label,
                ));
            }
        }
    }

    for rel in schema.relations {
        if !schema.label_holds(rel.field, rel.when_label, raw) {
            continue;
        }
        let other_holds = schema.label_holds(rel.other_field, rel.other_label, raw);
        let rule = match rel.kind {
            FieldRelationKind::Requires if !other_holds => Rule::Requires,
            FieldRelationKind::Conflicts if other_holds => Rule::Conflicts,
            _ => continue,
        };
        let value = schema
            .field(rel.field)
            .map_or(0, |f| Schema::value_of(f, raw));
        refusals.push(Refusal {
            other_field: Some(rel.other_field),
            other_label: Some(rel.other_label),
            ..Refusal::field_value(rule, rel.field, value, Some(rel.when_label))
        });
    }

    Verdict { refusals }
}

/// An allow word and a deny word over the same layout. Deny wins.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Policy {
    /// Bits a request may set.
    pub allow: u128,
    /// Bits a request must never set, even when allowed.
    pub deny: u128,
}

impl Policy {
    /// Builds a policy from an allow word and a deny word.
    #[must_use]
    pub const fn new(allow: u128, deny: u128) -> Self {
        Self { allow, deny }
    }

    /// True when every bit of `required` is allowed and none is denied.
    #[must_use]
    pub const fn allows(&self, required: u128) -> bool {
        required & self.deny == 0 && required & !self.allow == 0
    }
}

/// Checks a required word against a policy, after [`check`] on the word itself.
///
/// Each required bit set in `deny` is [`Rule::Denied`]; each other required
/// bit missing from `allow` is [`Rule::Missing`].
#[must_use]
pub fn authorize(schema: &Schema<'_>, required: u128, policy: &Policy) -> Verdict {
    let mut verdict = check(schema, required);
    for field in schema.fields {
        let wanted = required & field.mask;
        let denied = wanted & policy.deny;
        let missing = wanted & !policy.allow & !policy.deny;
        refuse_bits(
            schema,
            field,
            required,
            denied,
            Rule::Denied,
            &mut verdict.refusals,
        );
        refuse_bits(
            schema,
            field,
            required,
            missing,
            Rule::Missing,
            &mut verdict.refusals,
        );
    }
    verdict
}

/// Names `bits` (all inside `field`) through `FLAGS`, and any bits no flag
/// names through the field and its value.
fn refuse_bits(
    schema: &Schema<'_>,
    field: &BitFieldSpec,
    required: u128,
    bits: u128,
    rule: Rule,
    out: &mut Vec<Refusal>,
) {
    if bits == 0 {
        return;
    }
    let mut unnamed = bits;
    for flag in schema.flags.iter().filter(|f| f.field == field.name) {
        let bit = field.shift + flag.bit;
        let mask = 1u128 << bit;
        if bits & mask != 0 {
            unnamed &= !mask;
            out.push(Refusal {
                bit: Some(bit),
                ..Refusal::field_value(
                    rule,
                    field.name,
                    Schema::value_of(field, required),
                    Some(flag.name),
                )
            });
        }
    }
    if unnamed != 0 {
        let value = Schema::value_of(field, required);
        out.push(Refusal::field_value(
            rule,
            field.name,
            value,
            schema.label_for(field.name, value),
        ));
    }
}
