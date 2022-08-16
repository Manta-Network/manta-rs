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

use alloc::collections::BTreeMap;
use serde::{Deserialize, Serialize};

/// Has Contributed
pub trait HasContributed {
    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets the participant as contributed.
    fn set_contributed(&mut self);
}

/// Registry
#[derive(Default, Serialize, Deserialize)]
#[serde(bound(
    serialize = "K: Serialize, V: Serialize",
    deserialize = "K: Deserialize<'de>, V: Deserialize<'de>"
))]
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
