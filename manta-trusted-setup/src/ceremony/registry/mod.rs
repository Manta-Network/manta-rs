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

//! Trusted Setup Ceremony Registry

#[cfg(feature = "csv")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "csv")))]
use crate::ceremony::registry::csv::Record;

#[cfg(feature = "std")]
use std::{
    collections::{hash_map::Entry, HashMap},
    hash::Hash,
};

#[cfg(feature = "csv")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "csv")))]
pub mod csv;

/// Participant Registry
pub trait Registry<I, P> {
    /// Builds a new [`Registry`].
    fn new() -> Self;

    /// Registers the `id` and `participant` into `self` returning `false` if the `participant` is
    /// already registered or their registration would conflict with another existing participant.
    fn insert(&mut self, id: I, participant: P) -> bool;

    /// Returns a shared reference to the participant with the given `id` if they are registered.
    fn get(&self, id: &I) -> Option<&P>;

    /// Returns a mutable reference to the participant with the given `id` if they are registered.
    fn get_mut(&mut self, id: &I) -> Option<&mut P>;

    /// Returns the length of `self`.
    fn len(&self) -> usize;

    /// Returns true if `self.len() == 0`.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Registry Configuration
#[cfg(feature = "csv")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "csv")))]
pub trait Configuration {
    /// Identifier Type
    type Identifier;

    /// Participant Type
    type Participant;

    /// Record Type
    type Record: Record<Self::Identifier, Self::Participant>;

    /// Registry Type
    type Registry: Registry<Self::Identifier, Self::Participant>;
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<I, P> Registry<I, P> for HashMap<I, P>
where
    I: Eq + Hash,
{
    #[inline]
    fn new() -> Self {
        Self::new()
    }

    #[inline]
    fn insert(&mut self, key: I, value: P) -> bool {
        match self.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(value);
                true
            }
            _ => false,
        }
    }

    #[inline]
    fn get(&self, id: &I) -> Option<&P> {
        self.get(id)
    }

    #[inline]
    fn get_mut(&mut self, id: &I) -> Option<&mut P> {
        self.get_mut(id)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }
}
