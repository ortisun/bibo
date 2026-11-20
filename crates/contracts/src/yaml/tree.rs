//! The tree the restricted reader builds, and a serde deserializer over it.
//!
//! The tree keeps the line and column of every value and every key. The deserializer uses them to
//! put a key path and a line on every error, which `serde_json` cannot do: `items[0].colour` at
//! line 5 is something a person can fix, `unknown field` alone is not.

use std::fmt;

use serde::de::value::StrDeserializer;
use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};
use serde_json::{Map, Number, Value};

/// A value with the place it was written.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// Line, counting from 1.
    pub line: usize,
    /// Column, counting from 1.
    pub column: usize,
    /// The value.
    pub content: Content,
}

/// What a node holds. There is no null: the reader refuses it.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// `true` or `false`.
    Bool(bool),
    /// An integer that fits `i64`.
    Int(i64),
    /// An integer above `i64::MAX`.
    UInt(u64),
    /// A number with a fractional part.
    Float(f64),
    /// Text.
    Str(String),
    /// A sequence.
    Seq(Vec<Node>),
    /// A mapping, in the order it was written. Keys are unique.
    Map(Vec<Entry>),
}

/// One key and its value.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The key.
    pub key: String,
    /// Line of the key, counting from 1.
    pub line: usize,
    /// Column of the key, counting from 1.
    pub column: usize,
    /// The value.
    pub value: Node,
}

impl Node {
    /// The same document as JSON. Recursion is bounded by the nesting limit the reader enforced.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match &self.content {
            Content::Bool(b) => Value::Bool(*b),
            Content::Int(i) => Value::Number((*i).into()),
            Content::UInt(u) => Value::Number((*u).into()),
            // The reader only builds finite floats, so this cannot be `None`.
            Content::Float(f) => Number::from_f64(*f).map_or(Value::Null, Value::Number),
            Content::Str(s) => Value::String(s.clone()),
            Content::Seq(items) => Value::Array(items.iter().map(Node::to_json).collect()),
            Content::Map(entries) => {
                let mut map = Map::new();
                for entry in entries {
                    map.insert(entry.key.clone(), entry.value.to_json());
                }
                Value::Object(map)
            }
        }
    }
}

// ------------------------------------------------------------------------------------------
// Errors from decoding
// ------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Key(String),
    Index(usize),
}

/// A decoding error that grows a path and a line as it travels up through the containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub(crate) message: String,
    path: Vec<Segment>,
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
}

impl DecodeError {
    fn at_key(mut self, key: &str, line: usize, column: usize) -> Self {
        if self.line.is_none() {
            self.line = Some(line);
            self.column = Some(column);
        }
        self.path.insert(0, Segment::Key(key.to_owned()));
        self
    }

    fn at_index(mut self, index: usize, line: usize, column: usize) -> Self {
        if self.line.is_none() {
            self.line = Some(line);
            self.column = Some(column);
        }
        self.path.insert(0, Segment::Index(index));
        self
    }

    pub(crate) fn set_position_if_missing(&mut self, line: usize, column: usize) {
        if self.line.is_none() {
            self.line = Some(line);
            self.column = Some(column);
        }
    }

    /// The path written like `items[0].colour`, or `None` for the document itself.
    pub(crate) fn rendered_path(&self) -> Option<String> {
        if self.path.is_empty() {
            return None;
        }
        let mut text = String::new();
        for segment in &self.path {
            match segment {
                Segment::Key(key) => {
                    if !text.is_empty() {
                        text.push('.');
                    }
                    text.push_str(key);
                }
                Segment::Index(index) => text.push_str(&format!("[{index}]")),
            }
        }
        Some(text)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DecodeError {}

impl de::Error for DecodeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self {
            message: message.to_string(),
            path: Vec::new(),
            line: None,
            column: None,
        }
    }
}

// ------------------------------------------------------------------------------------------
// The deserializer
// ------------------------------------------------------------------------------------------

/// Deserializes a [`Node`] into any `serde` type.
pub(crate) struct NodeDeserializer<'de>(pub(crate) &'de Node);

impl<'de> de::Deserializer<'de> for NodeDeserializer<'de> {
    type Error = DecodeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match &self.0.content {
            Content::Bool(b) => visitor.visit_bool(*b),
            Content::Int(i) => visitor.visit_i64(*i),
            Content::UInt(u) => visitor.visit_u64(*u),
            Content::Float(f) => visitor.visit_f64(*f),
            Content::Str(s) => visitor.visit_borrowed_str(s),
            Content::Seq(items) => visitor.visit_seq(Sequence {
                items: items.iter().enumerate(),
            }),
            Content::Map(entries) => visitor.visit_map(Mapping {
                entries: entries.iter(),
                pending: None,
            }),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        // There is no null, so a value that is present is `Some`.
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        match &self.0.content {
            Content::Str(s) => visitor.visit_enum(StringVariant(s)),
            _ => Err(de::Error::custom(
                "expected the name of one of the allowed values written as text",
            )),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        unit unit_struct seq tuple tuple_struct map struct identifier ignored_any
    }
}

struct StringVariant<'a>(&'a str);

impl<'de> EnumAccess<'de> for StringVariant<'de> {
    type Error = DecodeError;
    type Variant = UnitOnly;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, UnitOnly), DecodeError> {
        let deserializer: StrDeserializer<'_, DecodeError> = self.0.into_deserializer();
        seed.deserialize(deserializer)
            .map(|value| (value, UnitOnly))
    }
}

struct UnitOnly;

impl<'de> de::VariantAccess<'de> for UnitOnly {
    type Error = DecodeError;

    fn unit_variant(self) -> Result<(), DecodeError> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        _seed: T,
    ) -> Result<T::Value, DecodeError> {
        Err(de::Error::custom("this value takes no data"))
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, DecodeError> {
        Err(de::Error::custom("this value takes no data"))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, DecodeError> {
        Err(de::Error::custom("this value takes no data"))
    }
}

struct Sequence<'de> {
    items: std::iter::Enumerate<std::slice::Iter<'de, Node>>,
}

impl<'de> SeqAccess<'de> for Sequence<'de> {
    type Error = DecodeError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, DecodeError> {
        match self.items.next() {
            None => Ok(None),
            Some((index, node)) => seed
                .deserialize(NodeDeserializer(node))
                .map(Some)
                .map_err(|e| e.at_index(index, node.line, node.column)),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len())
    }
}

struct Mapping<'de> {
    entries: std::slice::Iter<'de, Entry>,
    pending: Option<&'de Entry>,
}

impl<'de> MapAccess<'de> for Mapping<'de> {
    type Error = DecodeError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, DecodeError> {
        match self.entries.next() {
            None => Ok(None),
            Some(entry) => {
                self.pending = Some(entry);
                seed.deserialize(KeyDeserializer(&entry.key))
                    .map(Some)
                    // An unknown field is raised here, while the key is being read.
                    .map_err(|e| e.at_key(&entry.key, entry.line, entry.column))
            }
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, DecodeError> {
        let Some(entry) = self.pending.take() else {
            return Err(de::Error::custom("a value was requested before its key"));
        };
        seed.deserialize(NodeDeserializer(&entry.value))
            .map_err(|e| e.at_key(&entry.key, entry.value.line, entry.value.column))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

struct KeyDeserializer<'de>(&'de str);

impl<'de> de::Deserializer<'de> for KeyDeserializer<'de> {
    type Error = DecodeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        visitor.visit_borrowed_str(self.0)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier
        ignored_any
    }
}
