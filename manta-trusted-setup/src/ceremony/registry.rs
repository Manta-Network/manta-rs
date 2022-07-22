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
use core::{hash::Hash, marker::PhantomData};
use std::collections::BTreeMap;

/// Map used by registry.
pub trait Map<K, V>: Default {
    /// Inserts a key-value pair into the map.
    /// If the map did not have this key present, `None` is returned.
    /// If the map did have this key present, the value is updated, and the old value is returned.
    fn _insert(&mut self, key: K, value: V) -> Option<V>;

    /// Return `true` if the map contains a value for the specified key.
    fn _contains_key(&self, key: &K) -> bool;

    /// Returns a reference to the value corresponding to the key.
    fn _get(&self, key: &K) -> Option<&V>;
}

/// Registry for the ceremony.
pub struct Registry<K, V, M>
where
    M: Map<K, V>,
{
    map: M,
    __: PhantomData<(K, V)>,
}

impl<K, V, M> Default for Registry<K, V, M>
where
    M: Map<K, V>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V, M> Registry<K, V, M>
where
    M: Map<K, V>,
{
    /// Returns an empty registry.
    pub fn new() -> Self {
        Self {
            map: M::default(),
            __: PhantomData,
        }
    }

    /// Add a participant to the registry.
    ///
    /// # Errors
    /// If the participant is already registered, returns `CeremonyError::ParticipantAlreadyRegistered`.
    pub fn insert(&mut self, id: K, participant: V) -> Result<(), CeremonyError>
    where
        K: Hash + Eq,
    {
        if self.map._contains_key(&id) {
            return Err(CeremonyError::ParticipantAlreadyRegistered);
        }
        self.map._insert(id, participant);
        Ok(())
    }

    /// Get the participant data from the registry using their `id`. Returns `None` if the participant is not registered.
    pub fn get(&self, id: &K) -> Option<&V> {
        self.map._get(id)
    }
}

#[cfg(feature = "std")]
mod std_impl {
    use crate::ceremony::registry::Map;
    use std::{
        collections::HashMap,
        hash::{BuildHasher, Hash},
    };

    impl<K, V, S> Map<K, V> for HashMap<K, V, S>
    where
        K: Eq + Hash,
        S: BuildHasher + Default,
    {
        fn _insert(&mut self, key: K, value: V) -> Option<V> {
            self.insert(key, value)
        }

        fn _contains_key(&self, key: &K) -> bool {
            self.contains_key(key)
        }

        fn _get(&self, key: &K) -> Option<&V> {
            self.get(key)
        }
    }
}

impl<K, V> Map<K, V> for BTreeMap<K, V>
where
    K: Ord,
{
    fn _insert(&mut self, key: K, value: V) -> Option<V> {
        self.insert(key, value)
    }

    fn _contains_key(&self, key: &K) -> bool {
        self.contains_key(key)
    }

    fn _get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
}
