// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Registry

use crate::ceremony::CeremonyError;
use alloc::collections::{
    btree_map::Entry::{Occupied, Vacant},
    BTreeMap,
};

/// Map
pub trait Map: Default {
    /// Key Type
    type Key;

    /// Value Type
    type Value;

    /// Inserts a key into the map and gets a reference of the value. Returns `None`
    /// if the key already exists.
    fn insert_and_get_reference(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Option<&Self::Value>;

    /// Removes a key from the map and returns `None` if the key does not exist.
    fn remove(&mut self, key: &Self::Key) -> Option<Self::Value>;

    /// Gets the value for a given `key` and returns `None` if the key does not exist.
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
}

/// Registry
#[derive(Default)]
pub struct Registry<M>
where
    M: Map,
{
    map: M,
}

impl<M> Registry<M>
where
    M: Map,
{
    /// Adds a participant `(id, value)` to the registry, and returns a reference to `value` in the registry.
    #[inline]
    pub fn register(&mut self, id: M::Key, value: M::Value) -> Result<&M::Value, CeremonyError> {
        self.map
            .insert_and_get_reference(id, value)
            .map_or_else(|| Err(CeremonyError::AlreadyRegistered), Ok)
    }

    /// Unregisters a participant from the registry.
    #[inline]
    pub fn unregister(&mut self, id: &M::Key) -> Result<M::Value, CeremonyError> {
        self.map.remove(id).ok_or(CeremonyError::NotRegistered)
    }

    /// Gets the participant value given the `id` and returns `None` if the participant is not registered.
    #[inline]
    pub fn get(&self, id: &M::Key) -> Option<&M::Value> {
        self.map.get(id)
    }
}

impl<K, V> Map for BTreeMap<K, V>
where
    K: Ord,
{
    type Key = K;
    type Value = V;

    #[inline]
    fn insert_and_get_reference(&mut self, key: K, value: V) -> Option<&V> {
        match self.entry(key) {
            Occupied(_) => None,
            Vacant(entry) => Some(entry.insert(value)),
        }
    }

    #[inline]
    fn remove(&mut self, key: &Self::Key) -> Option<Self::Value> {
        self.remove(key)
    }

    #[inline]
    fn get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if registry is valid.
    #[test]
    fn registry_is_valid() {
        let mut registry = Registry::<BTreeMap<_, _>>::default();
        registry
            .register(1, "Alice")
            .expect("(1, Alice) should be inserted.");
        registry
            .register(2, "Bob")
            .expect("(2, Bob) should be inserted.");
        registry
            .register(3, "Alice")
            .expect("(3, Alice) should be inserted even if value is the same as (1, Alice).");
        assert_eq!(
            registry.register(2, "Charlie"),
            Err(CeremonyError::AlreadyRegistered),
            "Duplicated participant should not be inserted."
        );
        assert_eq!(registry.get(&2), Some(&"Bob"), "Get should succeed.");
        assert_eq!(
            registry.unregister(&2),
            Ok("Bob"),
            "Unregsiter should succeed."
        );
        assert_eq!(
            registry.unregister(&2),
            Err(CeremonyError::NotRegistered),
            "Unregister should failed."
        );
        assert_eq!(registry.get(&2), None, "Get should failed.");
    }
}
