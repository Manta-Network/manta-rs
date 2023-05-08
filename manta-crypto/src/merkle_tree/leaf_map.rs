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

//! Leaf Map

use crate::merkle_tree::{Configuration, LeafDigest};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{fmt::Debug, hash::Hash};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::collections::hash_map::HashMap;

/// Leaf Map
pub trait LeafMap<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the number of stored leaf digests in `self`.
    fn len(&self) -> usize;

    /// Checks whether `self` is empty.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the [`LeafDigest`] stored at `index`.
    fn get(&self, index: usize) -> Option<&LeafDigest<C>>;

    /// Returns the current (i.e. rightmost) [`LeafDigest`] in `self`.
    #[inline]
    fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.get(self.current_index()?)
    }

    /// Returns the current index of `self`. Returns `None` if `self` has not had leaves at any point.
    fn current_index(&self) -> Option<usize>;

    /// Returns the index at which `leaf_digest` is stored. Default implementation always returns `None`,
    /// non-trivial implementations require [`LeafDigest<C>`] to implement the [`PartialEq`] trait.
    #[inline]
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        let _ = leaf_digest;
        None
    }

    /// Pushes `leaf_digest` to the right-most position of `self`.
    fn push(&mut self, leaf_digest: LeafDigest<C>);

    /// Extends `self` with `leaf_digests`.
    #[inline]
    fn extend(&mut self, leaf_digests: Vec<LeafDigest<C>>) {
        for leaf_digest in leaf_digests.into_iter() {
            self.push(leaf_digest)
        }
    }

    /// Marks the [`LeafDigest`] at `index` for removal.
    fn mark(&mut self, index: usize);

    /// Checks whether the [`LeafDigest`] at `index` is marked for removal. Returns `None` if there
    /// is no [`LeafDigest`] stored at `index`.
    fn is_marked(&self, index: usize) -> Option<bool>;

    /// Checks whether the [`LeafDigest`] at `index` is either already deleted or marked for removal.
    /// Returns false if `index` is the current index.
    #[inline]
    fn is_marked_or_removed(&self, index: usize) -> bool {
        if let Some(current_index) = self.current_index() {
            if index >= current_index {
                false
            } else {
                self.is_marked(index).unwrap_or(true)
            }
        } else {
            false
        }
    }

    /// Tries to remove the [`LeafDigest`] stored at `index`. Fails when trying to remove the current leaf.
    fn remove(&mut self, index: usize) -> bool;

    /// Builds a [`LeafMap`] from `leaf_digests`.
    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self;

    /// Returns a vector with all [`LeafDigest`]s in `self`.
    #[inline]
    fn leaf_digests(&self) -> Vec<&LeafDigest<C>> {
        (0..self.len()).filter_map(|x| self.get(x)).collect()
    }

    /// Returns a vector with all [`LeafDigest`]s, consuming `self`.
    fn into_leaf_digests(self) -> Vec<LeafDigest<C>>;

    /// Returns a vector with all marked [`LeafDigest`]s in `self`.
    #[inline]
    fn marked_leaf_digests(&self) -> Vec<&LeafDigest<C>> {
        (0..self.len())
            .filter(|&index| self.is_marked(index).unwrap_or(false))
            .map(|x| self.get(x).unwrap())
            .collect()
    }
}

/// Trivial Leaf Vector
///
/// This struct implements [`LeafMap`] in the most trivial way possible, i.e.,
/// it does not mark nor remove any leaves.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "LeafDigest<C>: Deserialize<'de>",
            serialize = "LeafDigest<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq")
)]
pub struct TrivialLeafVec<C>(Vec<LeafDigest<C>>)
where
    C: Configuration + ?Sized;

impl<C> LeafMap<C> for TrivialLeafVec<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: PartialEq,
{
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn get(&self, index: usize) -> Option<&LeafDigest<C>> {
        self.0.get(index)
    }

    #[inline]
    fn current_index(&self) -> Option<usize> {
        if self.is_empty() {
            None
        } else {
            Some(self.len() - 1)
        }
    }

    #[inline]
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.0.iter().position(|l| l == leaf_digest)
    }

    #[inline]
    fn push(&mut self, leaf_digest: LeafDigest<C>) {
        self.0.push(leaf_digest);
    }

    #[inline]
    fn extend(&mut self, leaf_digests: Vec<LeafDigest<C>>) {
        self.0.extend(leaf_digests)
    }

    #[inline]
    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self {
        Self(leaf_digests)
    }

    #[inline]
    fn into_leaf_digests(self) -> Vec<LeafDigest<C>> {
        self.0
    }

    #[inline]
    fn mark(&mut self, index: usize) {
        let _ = index;
    }

    #[inline]
    fn is_marked(&self, index: usize) -> Option<bool> {
        self.get(index).map(|_| false)
    }

    #[inline]
    fn remove(&mut self, index: usize) -> bool {
        let _ = index;
        false
    }
}

/// Leaf Vector
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "LeafDigest<C>: Deserialize<'de>",
            serialize = "LeafDigest<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq")
)]
pub struct LeafVec<C>
where
    C: Configuration + ?Sized,
{
    /// Vector of leaf digests with markings
    vec: Vec<(bool, LeafDigest<C>)>,
}

impl<C> LeafMap<C> for LeafVec<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: PartialEq,
{
    #[inline]
    fn len(&self) -> usize {
        self.vec.len()
    }

    #[inline]
    fn get(&self, index: usize) -> Option<&LeafDigest<C>> {
        Some(&self.vec.get(index)?.1)
    }

    #[inline]
    fn current_index(&self) -> Option<usize> {
        if self.is_empty() {
            None
        } else {
            Some(self.len() - 1)
        }
    }

    #[inline]
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.vec.iter().position(|(_, l)| l == leaf_digest)
    }

    #[inline]
    fn push(&mut self, leaf_digest: LeafDigest<C>) {
        self.vec.push((false, leaf_digest));
    }

    #[inline]
    fn extend(&mut self, leaf_digests: Vec<LeafDigest<C>>) {
        self.vec
            .extend(leaf_digests.into_iter().map(|digest| (false, digest)))
    }

    #[inline]
    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self {
        Self {
            vec: leaf_digests.into_iter().map(|x| (false, x)).collect(),
        }
    }

    #[inline]
    fn into_leaf_digests(self) -> Vec<LeafDigest<C>> {
        self.vec.into_iter().map(|(_, digest)| digest).collect()
    }

    #[inline]
    fn mark(&mut self, index: usize) {
        if let Some((b, _)) = self.vec.get_mut(index) {
            *b = true
        };
    }

    #[inline]
    fn is_marked(&self, index: usize) -> Option<bool> {
        Some(self.vec.get(index)?.0)
    }

    #[inline]
    fn remove(&mut self, index: usize) -> bool {
        let _ = index;
        false
    }
}

/// Leaf BTree Map
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "LeafDigest<C>: Deserialize<'de>",
            serialize = "LeafDigest<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq"),
    PartialEq(bound = "LeafDigest<C>: PartialEq")
)]
pub struct LeafBTreeMap<C>
where
    C: Configuration + ?Sized,
{
    /// Hash map of marked leaf digests
    map: BTreeMap<usize, (bool, LeafDigest<C>)>,

    /// Last index
    last_index: Option<usize>,
}

impl<C> LeafMap<C> for LeafBTreeMap<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: PartialEq,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    fn get(&self, index: usize) -> Option<&LeafDigest<C>> {
        Some(&self.map.get(&index)?.1)
    }

    #[inline]
    fn current_index(&self) -> Option<usize> {
        self.last_index
    }

    #[inline]
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.map.iter().position(|(_, (_, l))| l == leaf_digest)
    }

    #[inline]
    fn push(&mut self, leaf_digest: LeafDigest<C>) {
        self.last_index = Some(self.last_index.map(|index| index + 1).unwrap_or(0));
        self.map.insert(
            self.last_index
                .expect("This cannot fail because of the computation above."),
            (false, leaf_digest),
        );
    }

    #[inline]
    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self {
        let digest_count = leaf_digests.len();
        if digest_count == 0 {
            Self {
                map: Default::default(),
                last_index: None,
            }
        } else {
            Self {
                map: leaf_digests
                    .into_iter()
                    .map(|x| (false, x))
                    .enumerate()
                    .collect::<BTreeMap<usize, (bool, LeafDigest<C>)>>(),
                last_index: Some(digest_count - 1),
            }
        }
    }

    #[inline]
    fn into_leaf_digests(self) -> Vec<LeafDigest<C>> {
        self.map
            .into_iter()
            .map(|(_, (_, digest))| digest)
            .collect()
    }

    #[inline]
    fn mark(&mut self, index: usize) {
        if let Some((b, _)) = self.map.get_mut(&index) {
            *b = true
        };
    }

    #[inline]
    fn is_marked(&self, index: usize) -> Option<bool> {
        Some(self.map.get(&index)?.0)
    }

    #[inline]
    fn remove(&mut self, index: usize) -> bool {
        match self.last_index {
            Some(current_index) if index == current_index => false,
            _ => !matches!(self.map.remove(&index), None),
        }
    }
}

/// Leaf Hash Map
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "LeafDigest<C>: Deserialize<'de>",
            serialize = "LeafDigest<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq"),
    PartialEq(bound = "LeafDigest<C>: PartialEq")
)]
pub struct LeafHashMap<C>
where
    C: Configuration + ?Sized,
{
    /// Hash map of marked leaf digests
    map: HashMap<usize, (bool, LeafDigest<C>)>,

    /// Last index
    last_index: Option<usize>,
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<C> LeafMap<C> for LeafHashMap<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: PartialEq,
{
    #[inline]
    fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    fn get(&self, index: usize) -> Option<&LeafDigest<C>> {
        Some(&self.map.get(&index)?.1)
    }

    #[inline]
    fn current_index(&self) -> Option<usize> {
        self.last_index
    }

    #[inline]
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.map.iter().position(|(_, (_, l))| l == leaf_digest)
    }

    #[inline]
    fn push(&mut self, leaf_digest: LeafDigest<C>) {
        self.last_index = Some(self.last_index.map(|index| index + 1).unwrap_or(0));
        self.map.insert(
            self.last_index
                .expect("This cannot fail because of the computation above."),
            (false, leaf_digest),
        );
    }

    #[inline]
    fn from_vec(leaf_digests: Vec<LeafDigest<C>>) -> Self {
        let digest_count = leaf_digests.len();
        if digest_count == 0 {
            Self {
                map: Default::default(),
                last_index: None,
            }
        } else {
            Self {
                map: leaf_digests
                    .into_iter()
                    .map(|x| (false, x))
                    .enumerate()
                    .collect::<HashMap<usize, (bool, LeafDigest<C>)>>(),
                last_index: Some(digest_count - 1),
            }
        }
    }

    #[inline]
    fn into_leaf_digests(self) -> Vec<LeafDigest<C>> {
        self.map
            .into_iter()
            .map(|(_, (_, digest))| digest)
            .collect()
    }

    #[inline]
    fn mark(&mut self, index: usize) {
        if let Some((b, _)) = self.map.get_mut(&index) {
            *b = true
        };
    }

    #[inline]
    fn is_marked(&self, index: usize) -> Option<bool> {
        Some(self.map.get(&index)?.0)
    }

    #[inline]
    fn remove(&mut self, index: usize) -> bool {
        match self.last_index {
            Some(current_index) if index == current_index => false,
            _ => !matches!(self.map.remove(&index), None),
        }
    }
}
