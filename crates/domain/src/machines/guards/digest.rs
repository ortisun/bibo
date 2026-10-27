//! The digest of the facts a guard was checked on (ADR 0014 decision 3).
//!
//! [`evaluate`](super::evaluate) returns a [`GuardCleared`](super::GuardCleared) that carries the
//! SHA-256 of the facts the guard held on. The engine writes it into the event that announces the
//! move, so the stored record shows what was true when the move was made.
//!
//! # The text that is hashed
//!
//! One line per field, in the order the fields are declared: `name=value` and a newline.
//!
//! * A boolean is `true` or `false`.
//! * A number is written in decimal.
//! * A timestamp is written with [`Timestamp::as_text`], so `10:00:00Z` and `10:00:00.000Z`
//!   give different digests: the digest is of what was recorded, not of the instant.
//! * A digest, an identifier and a status are written as their text.
//! * An absent option is `-`, a present one is its value.
//! * A list is `[a,b,c]`, and a nested struct is `{name=value,name=value}`.
//!
//! # Why a macro defines the structs
//!
//! [`facts!`] defines a facts struct and the code that renders it from the same field list, so a
//! field added later is in the digest the moment it exists. A hand-written render function could
//! forget it.

use super::stage_run::{EnvironmentCause, NotApplicableBasis};
use crate::contracts::stage_contract::RetryClass;
use crate::ids::{StageRunId, TaskNodeId};
use crate::machines::failure::FailureClass;
use crate::machines::limits::{RepairCap, ReworkCap};
use crate::machines::snapshot::{BlockDisposition, SandboxState};
use crate::state::{AttemptStatus, JobStatus, StageRunStatus, TaskNodeStatus};
use crate::values::{Sha256Digest, Timestamp};
use crate::vocabulary::{GateOutcome, HumanRole, StageKind};

/// A value that can be written into the text a digest is taken over.
pub trait FactValue {
    /// The value as it appears after the `=` of a line.
    fn render(&self) -> String;
}

/// A struct of facts: the fields in declaration order, each already rendered.
pub trait Facts {
    /// `(name, rendered value)` for each field, in the order the fields are declared.
    fn fields(&self) -> Vec<(&'static str, String)>;
}

/// The lines of `facts`, `name=value` and a newline each. This is the text that is hashed.
#[must_use]
pub fn render_lines(facts: &dyn Facts) -> String {
    let mut text = String::new();
    for (name, value) in facts.fields() {
        text.push_str(name);
        text.push('=');
        text.push_str(&value);
        text.push('\n');
    }
    text
}

/// The nested form of a struct: `{name=value,name=value}`.
#[must_use]
pub fn render_nested(facts: &dyn Facts) -> String {
    let inner: Vec<String> = facts
        .fields()
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    format!("{{{}}}", inner.join(","))
}

/// The digest of `facts`.
#[must_use]
pub fn digest_of(facts: &dyn Facts) -> Sha256Digest {
    Sha256Digest::of(render_lines(facts).as_bytes())
}

macro_rules! via_display {
    ($($ty:ty),* $(,)?) => {
        $(
            impl FactValue for $ty {
                fn render(&self) -> String {
                    self.to_string()
                }
            }
        )*
    };
}

via_display!(
    bool,
    u8,
    u16,
    u32,
    u64,
    i64,
    usize,
    Sha256Digest,
    StageRunId,
    TaskNodeId,
    JobStatus,
    StageRunStatus,
    AttemptStatus,
    TaskNodeStatus,
    FailureClass,
    StageKind,
    HumanRole,
    GateOutcome,
    EnvironmentCause,
    RetryClass,
    SandboxState,
    BlockDisposition,
);

impl FactValue for NotApplicableBasis {
    fn render(&self) -> String {
        match self {
            NotApplicableBasis::DeterministicRule => "deterministic_rule",
            NotApplicableBasis::DomainProfile => "domain_profile",
            NotApplicableBasis::Policy => "policy",
            NotApplicableBasis::AgentOpinion => "agent_opinion",
        }
        .to_owned()
    }
}

impl FactValue for Timestamp {
    fn render(&self) -> String {
        self.as_text()
    }
}

impl FactValue for RepairCap {
    fn render(&self) -> String {
        self.get().to_string()
    }
}

impl FactValue for ReworkCap {
    fn render(&self) -> String {
        self.get().to_string()
    }
}

impl<T: FactValue + ?Sized> FactValue for &T {
    fn render(&self) -> String {
        (**self).render()
    }
}

impl<T: FactValue> FactValue for Option<T> {
    fn render(&self) -> String {
        match self {
            Some(value) => value.render(),
            None => "-".to_owned(),
        }
    }
}

impl<T: FactValue> FactValue for [T] {
    fn render(&self) -> String {
        let items: Vec<String> = self.iter().map(FactValue::render).collect();
        format!("[{}]", items.join(","))
    }
}

/// Defines a struct of facts and, from the same field list, the code that renders it for the
/// digest. Fields are all `pub`; attributes and doc comments pass through.
macro_rules! facts {
    (
        $(#[$meta:meta])*
        pub struct $name:ident $(<$lt:lifetime>)? {
            $(
                $(#[$fmeta:meta])*
                pub $field:ident : $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $name $(<$lt>)? {
            $(
                $(#[$fmeta])*
                pub $field: $ty,
            )*
        }

        impl $(<$lt>)? $crate::machines::guards::digest::Facts for $name $(<$lt>)? {
            fn fields(&self) -> ::std::vec::Vec<(&'static str, ::std::string::String)> {
                vec![
                    $(
                        (
                            stringify!($field),
                            $crate::machines::guards::digest::FactValue::render(&self.$field),
                        )
                    ),*
                ]
            }
        }

        impl $(<$lt>)? $crate::machines::guards::digest::FactValue for $name $(<$lt>)? {
            fn render(&self) -> ::std::string::String {
                $crate::machines::guards::digest::render_nested(self)
            }
        }
    };
}

pub(crate) use facts;

#[cfg(test)]
mod tests {
    use super::*;

    facts! {
        /// A small struct for the tests.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct Sample<'a> {
            /// A boolean.
            pub flag: bool,
            /// A number.
            pub count: u32,
            /// An absent option.
            pub missing: Option<u64>,
            /// A present option.
            pub present: Option<Timestamp>,
            /// A list.
            pub items: &'a [u32],
        }
    }

    fn sample(items: &[u32]) -> Sample<'_> {
        Sample {
            flag: true,
            count: 7,
            missing: None,
            present: Some(Timestamp::parse("2026-10-27T10:00:00.250Z").unwrap()),
            items,
        }
    }

    #[test]
    fn the_text_is_one_name_equals_value_line_per_field_in_field_order() {
        let text = render_lines(&sample(&[1, 2]));
        assert_eq!(
            text,
            "flag=true\ncount=7\nmissing=-\npresent=2026-10-27T10:00:00.250Z\nitems=[1,2]\n"
        );
    }

    #[test]
    fn the_digest_is_the_sha256_of_that_text() {
        let facts = sample(&[]);
        assert_eq!(
            digest_of(&facts),
            Sha256Digest::of(render_lines(&facts).as_bytes())
        );
    }

    #[test]
    fn equal_facts_give_equal_digests_and_a_changed_field_changes_the_digest() {
        let a = sample(&[1]);
        let b = sample(&[1]);
        assert_eq!(digest_of(&a), digest_of(&b));
        let mut c = sample(&[1]);
        c.flag = false;
        assert_ne!(digest_of(&a), digest_of(&c));
        assert_ne!(digest_of(&a), digest_of(&sample(&[1, 2])));
    }

    #[test]
    fn a_nested_struct_renders_inline() {
        facts! {
            /// An outer struct holding one inner struct.
            #[derive(Debug, Clone, Copy)]
            pub struct Outer<'a> {
                /// The inner struct.
                pub inner: Sample<'a>,
            }
        }
        let outer = Outer {
            inner: sample(&[3]),
        };
        assert_eq!(
            render_lines(&outer),
            "inner={flag=true,count=7,missing=-,present=2026-10-27T10:00:00.250Z,items=[3]}\n"
        );
    }

    #[test]
    fn a_timestamp_is_rendered_as_written_so_the_spelling_is_part_of_the_digest() {
        let short = Timestamp::parse("2026-10-27T10:00:00Z").unwrap();
        let long = Timestamp::parse("2026-10-27T10:00:00.000Z").unwrap();
        assert_eq!(short, long);
        assert_ne!(short.render(), long.render());
    }
}
