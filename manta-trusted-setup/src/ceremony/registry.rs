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
//! Registry for the ceremony.

use crate::ceremony::CeremonyError;
use alloc::collections::BTreeMap;

/// Map used by registry.
pub trait Map: Default {
    /// Key of map
    type Key;
    /// Value of map
    type Value;

    /// Try to insert a key into the map and get the reference of the value. If the key already exists,
    /// return `None`.
    fn try_insert_and_get_reference(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Option<&Self::Value>;

    /// Remove a key from the map. If the key does not exist, return `None`.
    fn remove(&mut self, key: &Self::Key) -> Option<Self::Value>;

    /// Return the value for the specified key. If the key does not exist, return `None`.
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
}

#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "M: Clone")
)]/// Registry for the ceremony.
pub struct Registry<M>
where
    M: Map,
{
    map: M,
}

impl<M> Default for Registry<M>
where
    M: Map,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<M> Registry<M>
where
    M: Map,
{
    /// Returns an empty registry.
    pub fn new() -> Self {
        Self { map: M::default() }
    }

    /// Add a participant to the registry, and return its reference in the registry.
    ///
    /// # Errors
    /// If the participant is already registered, returns [`CeremonyError::AlreadyRegistered`].
    pub fn try_register(
        &mut self,
        id: M::Key,
        participant: M::Value,
    ) -> Result<&M::Value, CeremonyError> {
        self.map
            .try_insert_and_get_reference(id, participant)
            .map_or_else(|| Err(CeremonyError::AlreadyRegistered), |v| Ok(v))
    }

    /// Unregister a participant from the registry, using their identifier.
    /// If the participant is not registered, returns [`CeremonyError::NotRegistered`].
    pub fn unregister(&mut self, id: &M::Key) -> Result<M::Value, CeremonyError> {
        self.map
            .remove(id)
            .ok_or_else(|| CeremonyError::NotRegistered)
    }

    /// Get the participant data from the registry using their `id`. Returns `None` if the participant is not registered.
    pub fn get(&self, id: &M::Key) -> Option<&M::Value> {
        self.map.get(id)
    }
}

#[cfg(feature = "std")]
mod std_impl {
    use crate::ceremony::registry::Map;
    use std::{
        collections::HashMap,
        hash::{BuildHasher, Hash},
    };

    impl<K, V, S> Map for HashMap<K, V, S>
    where
        K: Eq + Hash,
        S: BuildHasher + Default,
    {
        type Key = K;
        type Value = V;

        fn try_insert_and_get_reference(&mut self, key: K, value: V) -> Option<&V> {
            match self.entry(key) {
                std::collections::hash_map::Entry::Occupied(_) => None,
                std::collections::hash_map::Entry::Vacant(entry) => Some(entry.insert(value)),
            }
        }

        fn remove(&mut self, key: &Self::Key) -> Option<Self::Value> {
            self.remove(key)
        }

        fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
            self.get(key)
        }
    }
}

impl<K, V> Map for BTreeMap<K, V>
where
    K: Ord + Clone,
{
    type Key = K;
    type Value = V;

    fn try_insert_and_get_reference(&mut self, key: K, value: V) -> Option<&V> {
        match self.entry(key) {
            alloc::collections::btree_map::Entry::Occupied(_) => None,
            alloc::collections::btree_map::Entry::Vacant(entry) => Some(entry.insert(value)),
        }
    }

    fn remove(&mut self, key: &Self::Key) -> Option<Self::Value> {
        self.remove(key)
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
}

#[cfg(test)]
mod tests {
    use crate::ceremony::{registry::Registry, CeremonyError};
    use alloc::collections::BTreeMap;

    #[test]
    fn duplicate_participant() {
        let mut registry = Registry::<BTreeMap<_, _>>::new();
        registry
            .try_register(1, "alice")
            .expect("(1, alice) should be inserted");
        registry
            .try_register(2, "bob")
            .expect("(2, bob) should be inserted");
        registry
            .try_register(3, "alice")
            .expect("(3, alice) should be inserted even if value is the same as (1, alice)");
        assert_eq!(
            registry.try_register(2, "charlie"),
            Err(CeremonyError::AlreadyRegistered),
            "duplicate participant should not be inserted"
        );
    }
}
