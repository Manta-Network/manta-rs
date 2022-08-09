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

use alloc::collections::{BTreeMap, BTreeSet};

/// Registry
#[derive(Default)]
pub struct Registry<K, V>
where
    K: PartialEq + Ord,
{
    map: BTreeMap<K, V>,
    contributed_participants: BTreeSet<K>,
}

impl<K, V> Registry<K, V>
where
    K: PartialEq + Ord,
{
    /// Gets the participant value given the `id` and returns `None` if the participant is not registered.
    #[inline]
    pub fn get(&self, id: &K) -> Option<&V> {
        self.map.get(id)
    }

    #[inline]
    /// TODO
    pub fn has_contributed(&self, id: &K) -> bool {
        self.contributed_participants.contains(id)
    }
}
