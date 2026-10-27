//! Arrays with a size or uniqueness rule that the schemas state as `minItems` and `uniqueItems`.
//!
//! The wrapper types keep the order of the document. They are checked when they are read, so a
//! value of one of these types is never empty or duplicated against the rule of its field.

use std::collections::HashSet;
use std::hash::Hash;
use std::ops::Deref;

use crate::error::ValueError;

/// A list with at least one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
    /// Checks that the list is not empty.
    ///
    /// # Errors
    /// Returns a [`ValueError`] for an empty list.
    pub fn new(items: Vec<T>) -> Result<Self, ValueError> {
        if items.is_empty() {
            return Err(too_few::<1>());
        }
        Ok(Self(items))
    }

    /// The items, in document order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Gives back the plain list.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<'a, T> IntoIterator for &'a NonEmptyVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: serde::Serialize> serde::Serialize for NonEmptyVec<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for NonEmptyVec<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        Self::new(items).map_err(serde::de::Error::custom)
    }
}

/// A list in which no item appears twice, with at least `MIN` items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueVec<T, const MIN: usize = 0>(Vec<T>);

impl<T: Eq + Hash, const MIN: usize> UniqueVec<T, MIN> {
    /// Checks the minimum size and that no item repeats.
    ///
    /// # Errors
    /// Returns a [`ValueError`] for a short list or a repeated item.
    pub fn new(items: Vec<T>) -> Result<Self, ValueError> {
        if items.len() < MIN {
            return Err(too_few::<MIN>());
        }
        let mut seen = HashSet::with_capacity(items.len());
        if !items.iter().all(|item| seen.insert(item)) {
            return Err(ValueError::unquoted("list", "an item appears more than once"));
        }
        Ok(Self(items))
    }
}

impl<T, const MIN: usize> UniqueVec<T, MIN> {
    /// The items, in document order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Gives back the plain list.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MIN: usize> Deref for UniqueVec<T, MIN> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<'a, T, const MIN: usize> IntoIterator for &'a UniqueVec<T, MIN> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: serde::Serialize, const MIN: usize> serde::Serialize for UniqueVec<T, MIN> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T, const MIN: usize> serde::Deserialize<'de> for UniqueVec<T, MIN>
where
    T: serde::Deserialize<'de> + Eq + Hash,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        Self::new(items).map_err(serde::de::Error::custom)
    }
}

fn too_few<const MIN: usize>() -> ValueError {
    ValueError::unquoted("list", format!("it must hold at least {MIN} item(s)"))
}
