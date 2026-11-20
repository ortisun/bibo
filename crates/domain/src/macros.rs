//! Declarative macros that define the small wrapper types of the crate.
//!
//! They exist so that a closed set of names, an identifier or a patterned string is defined in
//! exactly one line, and so that every one of them reports a bad value in the same plain-English
//! form. The macros are crate-private. The types they produce are public.

/// A string wrapper that serializes as a plain JSON string and parses with `Self::parse`.
///
/// Implements `Display`, `FromStr`, `TryFrom<&str>`, `TryFrom<String>`, `AsRef<str>`, `Serialize`
/// and `Deserialize`. The type must have `fn parse(&str) -> Result<Self, ValueError>` and
/// `fn as_str(&self) -> &str`.
macro_rules! string_traits {
    ($name:ident) => {
        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl ::std::str::FromStr for $name {
            type Err = $crate::error::ValueError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
        impl ::std::convert::TryFrom<&str> for $name {
            type Error = $crate::error::ValueError;
            fn try_from(text: &str) -> Result<Self, Self::Error> {
                Self::parse(text)
            }
        }
        impl ::std::convert::TryFrom<String> for $name {
            type Error = $crate::error::ValueError;
            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }
        impl ::std::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let text = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                Self::parse(&text).map_err(::serde::de::Error::custom)
            }
        }
    };
}

/// A closed set of names with exact serialized spellings.
///
/// Generates the enum, `ALL` (in declaration order), `as_str`, `parse`, `Display`, `FromStr`,
/// `Serialize` and `Deserialize`. The spelling in the source is the spelling on the wire, so a
/// reader can see it without knowing a rename rule.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident ($what:literal) {
            $( $(#[$vmeta:meta])* $variant:ident = $text:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [$name] = &[ $( $name::$variant ),+ ];

            /// The exact name used in documents, in the database and in logs.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $name::$variant => $text ),+
                }
            }

            /// Reads one of the exact names. Any other text is an error that lists the choices.
            ///
            /// # Errors
            /// Returns a [`ValueError`](crate::error::ValueError) naming the allowed values.
            pub fn parse(text: &str) -> Result<Self, $crate::error::ValueError> {
                match text {
                    $( $text => Ok($name::$variant), )+
                    _ => Err($crate::error::ValueError::new(
                        $what,
                        text,
                        format!("expected one of: {}", [ $( $text ),+ ].join(", ")),
                    )),
                }
            }
        }

        $crate::macros::string_traits!($name);
    };
}

/// A string checked against one of the patterns the schemas declare.
macro_rules! patterned_string {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident ($what:literal) = $pattern:expr, $rule:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis struct $name(String);

        impl $name {
            /// The pattern, written exactly as in the schema.
            pub const PATTERN: &'static str = $pattern;

            /// Checks `text` against the pattern.
            ///
            /// # Errors
            /// Returns a [`ValueError`](crate::error::ValueError) when the text does not match.
            pub fn parse(text: &str) -> Result<Self, $crate::error::ValueError> {
                static REGEX: ::std::sync::LazyLock<::regex::Regex> =
                    ::std::sync::LazyLock::new(|| {
                        ::regex::Regex::new($pattern).expect("a schema pattern is a valid regex")
                    });
                if REGEX.is_match(text) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err($crate::error::ValueError::new($what, text, $rule))
                }
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        $crate::macros::string_traits!($name);
    };
}

/// A typed identifier: a lowercase, hyphenated UUID that cannot be mixed up with another kind.
macro_rules! uuid_id {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident ($what:literal)
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis struct $name(::uuid::Uuid);

        impl $name {
            /// Wraps a UUID that the `IdGenerator` port produced.
            #[must_use]
            pub const fn from_uuid(uuid: ::uuid::Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> ::uuid::Uuid {
                self.0
            }

            /// Reads the schema form: 36 characters, lowercase, hyphenated.
            ///
            /// # Errors
            /// Returns a [`ValueError`](crate::error::ValueError) for any other spelling.
            pub fn parse(text: &str) -> Result<Self, $crate::error::ValueError> {
                $crate::values::parse_uuid($what, text).map(Self)
            }

            /// The text form, which is also the form in documents.
            #[must_use]
            pub fn as_text(&self) -> String {
                self.0.hyphenated().to_string()
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }
        impl ::std::str::FromStr for $name {
            type Err = $crate::error::ValueError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(&self.0.hyphenated())
            }
        }
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                Self::parse(&text).map_err(::serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use patterned_string;
pub(crate) use string_enum;
pub(crate) use string_traits;
pub(crate) use uuid_id;
