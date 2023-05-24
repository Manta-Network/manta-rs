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

//! Nullifier Map

use alloc::{collections::BTreeSet, vec::Vec};

#[cfg(feature = "std")]
use {core::hash::Hash, std::collections::HashSet};

/// Nullifier Map
pub trait NullifierMap<T>: Default {
    /// Creates a new [`NullifierMap`].
    fn new() -> Self;

    /// Returns the number of elements in `self`
    fn len(&self) -> usize;

    /// Returns `true` if `self` contains no elements.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts `item` in `self`.
    fn insert(&mut self, item: T) -> bool;

    /// Extens `self` with `items`.
    fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>;

    /// Removes `item` from `self`.
    fn remove(&mut self, item: &T) -> bool;

    /// Checks if `self` contains `item`.
    fn contains_item(&self, item: &T) -> bool;
}

impl<T> NullifierMap<T> for Vec<T>
where
    T: PartialEq,
{
    #[inline]
    fn new() -> Self {
        Self::new()
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn insert(&mut self, item: T) -> bool {
        self.push(item);
        true
    }

    #[inline]
    fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>,
    {
        Extend::extend(self, items)
    }

    #[inline]
    fn remove(&mut self, item: &T) -> bool {
        if let Some(index) = self.iter().position(|x| x == item) {
            self.remove(index);
            true
        } else {
            false
        }
    }

    #[inline]
    fn contains_item(&self, item: &T) -> bool {
        self.contains(item)
    }
}

impl<T> NullifierMap<T> for BTreeSet<T>
where
    T: PartialEq + Ord,
{
    #[inline]
    fn new() -> Self {
        Self::new()
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn insert(&mut self, item: T) -> bool {
        self.insert(item)
    }

    #[inline]
    fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>,
    {
        Extend::extend(self, items)
    }

    #[inline]
    fn remove(&mut self, item: &T) -> bool {
        self.remove(item)
    }

    #[inline]
    fn contains_item(&self, item: &T) -> bool {
        self.contains(item)
    }
}

#[cfg(feature = "std")]
impl<T> NullifierMap<T> for HashSet<T>
where
    T: Hash + Eq,
{
    #[inline]
    fn new() -> Self {
        Self::new()
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn insert(&mut self, item: T) -> bool {
        self.insert(item)
    }

    #[inline]
    fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>,
    {
        Extend::extend(self, items)
    }

    #[inline]
    fn remove(&mut self, item: &T) -> bool {
        self.remove(item)
    }

    #[inline]
    fn contains_item(&self, item: &T) -> bool {
        self.contains(item)
    }
}
