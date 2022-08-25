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

use crate::ceremony::util::HasContributed;
use alloc::collections::BTreeMap;
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_pay::crypto::constraint::arkworks::codec::SerializationError;
use std::io::{Read, Write};

/// Registry
pub struct Registry<K, V>
where
    K: Ord,
{
    /// Map from key `K` to value `V`
    map: BTreeMap<K, V>,
}

impl<K, V> Registry<K, V>
where
    K: Ord,
{
    /// Builds a new [`Registry`].
    #[inline]
    pub fn new(map: BTreeMap<K, V>) -> Self {
        Self { map }
    }

    /// Inserts a `(key, value)` pair into registry.
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Result<(), &'static str> {
        match self.map.insert(key, value) {
            None => Ok(()),
            Some(_) => Err("Invalid insertion into registry."),
        }
    }

    /// Gets the participant value given the `id` and returns `None` if the participant is not registered.
    #[inline]
    pub fn get(&self, id: &K) -> Option<&V> {
        self.map.get(id)
    }

    /// Gets the mutable reference of participant value given the `id` and returns `None` if the participant is not registered.
    #[inline]
    pub fn get_mut(&mut self, id: &K) -> Option<&mut V> {
        self.map.get_mut(id)
    }

    /// Checks if `id` has contributed.
    #[inline]
    pub fn has_contributed(&self, id: &K) -> bool
    where
        V: HasContributed,
    {
        self.map
            .get(id)
            .map(|v| v.has_contributed())
            .unwrap_or(false)
    }
}

impl<K, V> CanonicalSerialize for Registry<K, V>
where
    K: Ord + CanonicalSerialize,
    V: CanonicalSerialize,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        self.map
            .serialize(&mut writer)
            .expect("Serializing should succeed");
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.map.serialized_size()
    }
}

impl<K, V> CanonicalDeserialize for Registry<K, V>
where
    K: Ord + CanonicalDeserialize,
    V: CanonicalDeserialize,
{
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        Ok(Self {
            map: CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing should succeed."),
        })
    }
}
