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

//! Assets
//!
//! This module defines the data structures and canonical encodings of a standard notion of "asset".
//! Assets are defined by an `AssetId` field and an `AssetValue` field. For describing an [`Asset`]
//! with a particular `AssetId` we use [`AssetMetadata`] to assign a symbol and decimals for
//! human-readable display purposes.

use alloc::{
    collections::btree_map::{BTreeMap, Entry as BTreeMapEntry},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::{
    borrow::Borrow,
    fmt::Debug,
    hash::Hash,
    iter::{self, FusedIterator},
    ops::{Add, AddAssign, Deref, Div, Sub, SubAssign},
    slice,
};
use derive_more::{Display, From};
use manta_crypto::{
    eclair::{
        self,
        alloc::{
            mode::{Public, Secret},
            Allocate, Allocator, Variable,
        },
        bool::{Assert, AssertEq, Bool, ConditionalSelect},
        num::Zero,
        ops::BitAnd,
        Has,
    },
    rand::{Rand, RngCore, Sample},
};
use manta_util::num::CheckedSub;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::{
    collections::hash_map::{Entry as HashMapEntry, HashMap, RandomState},
    hash::BuildHasher,
};

/// Asset
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Display, From, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[display(fmt = "{{id: {}, value: {}}}", id, value)]
pub struct Asset<I, V> {
    /// Asset Id
    pub id: I,

    /// Asset Value
    pub value: V,
}

impl<I, V> Asset<I, V> {
    /// Builds a new [`Asset`] from an `id` and a `value`.
    #[inline]
    pub const fn new(id: I, value: V) -> Self {
        Self { id, value }
    }

    /// Builds a new zero [`Asset`] with the given `id`.
    #[inline]
    pub fn zero(id: I) -> Self
    where
        V: Default,
    {
        Self::new(id, Default::default())
    }

    /// Returns `true` if `self` is a zero [`Asset`] of some asset id.
    #[inline]
    pub fn is_zero(&self) -> bool
    where
        V: Default + PartialEq,
    {
        self.value == Default::default()
    }

    /// Returns `true` if `self` is an empty [`Asset`], i.e. both the `id` and `value` are zero.
    #[inline]
    pub fn is_empty<COM>(&self, compiler: &mut COM) -> Bool<COM>
    where
        COM: Has<bool>,
        I: Zero<COM, Verification = Bool<COM>>,
        V: Zero<COM, Verification = Bool<COM>>,
        Bool<COM>: BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    {
        self.id
            .is_zero(compiler)
            .bitand(self.value.is_zero(compiler), compiler)
    }
}

impl<I, V> Add<V> for Asset<I, V>
where
    V: AddAssign,
{
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: V) -> Self::Output {
        self += rhs;
        self
    }
}

impl<I, V> AddAssign<V> for Asset<I, V>
where
    V: AddAssign,
{
    #[inline]
    fn add_assign(&mut self, rhs: V) {
        self.value += rhs;
    }
}

impl<I, V> From<Asset<I, V>> for (I, V) {
    #[inline]
    fn from(asset: Asset<I, V>) -> Self {
        (asset.id, asset.value)
    }
}

impl<'a, I, V> From<&'a Asset<I, V>> for (&'a I, &'a V) {
    #[inline]
    fn from(asset: &'a Asset<I, V>) -> Self {
        (&asset.id, &asset.value)
    }
}

impl<I, V> Sample for Asset<I, V>
where
    I: Sample,
    V: Sample,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.gen(), rng.gen())
    }
}

impl<I, V> Sub<V> for Asset<I, V>
where
    V: SubAssign,
{
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: V) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<I, V> SubAssign<V> for Asset<I, V>
where
    V: SubAssign,
{
    #[inline]
    fn sub_assign(&mut self, rhs: V) {
        self.value -= rhs;
    }
}

impl<I, V, COM> ConditionalSelect<COM> for Asset<I, V>
where
    COM: Has<bool>,
    I: ConditionalSelect<COM>,
    V: ConditionalSelect<COM>,
{
    #[inline]
    fn select(bit: &Bool<COM>, true_value: &Self, false_value: &Self, compiler: &mut COM) -> Self {
        Self::new(
            I::select(bit, &true_value.id, &false_value.id, compiler),
            V::select(bit, &true_value.value, &false_value.value, compiler),
        )
    }
}

impl<I, V, COM> eclair::cmp::PartialEq<Self, COM> for Asset<I, V>
where
    COM: Has<bool>,
    Bool<COM>: BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    I: eclair::cmp::PartialEq<I, COM>,
    V: eclair::cmp::PartialEq<V, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.id
            .eq(&rhs.id, compiler)
            .bitand(self.value.eq(&rhs.value, compiler), compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        compiler.assert_eq(&self.id, &rhs.id);
        compiler.assert_eq(&self.value, &rhs.value);
    }
}

impl<COM, I, V> Variable<Secret, COM> for Asset<I, V>
where
    I: Variable<Secret, COM>,
    V: Variable<Secret, COM>,
{
    type Type = Asset<I::Type, V::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(this.id.as_known(compiler), this.value.as_known(compiler))
    }
}

impl<COM, I, V> Variable<Public, COM> for Asset<I, V>
where
    I: Variable<Public, COM>,
    V: Variable<Public, COM>,
{
    type Type = Asset<I::Type, V::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(this.id.as_known(compiler), this.value.as_known(compiler))
    }
}

/// Asset List
///
/// Stores assets sorted by `I` as a flat key-value vector. This type can be relied on to maintain
/// sorted order for iterating.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Default(bound = ""), Eq, Hash, PartialEq)]
pub struct AssetList<I, V> {
    /// Sorted Asset Vector
    ///
    /// The elements of the vector are sorted by `I`. To insert/remove we perform a binary search
    /// on `I` and update `V` at that location.
    map: Vec<Asset<I, V>>,
}

impl<I, V> AssetList<I, V> {
    /// Builds a new empty [`AssetList`].
    #[inline]
    pub const fn new() -> Self {
        Self { map: Vec::new() }
    }

    /// Returns the number of entries stored in `self`.
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the number of entries in `self` is zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns the number of `AssetId`s that can be inserted into `self` before needing to
    /// reallocate.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// Finds the insertion point for an [`Asset`] with the given `id`, returning `Ok` if there is
    /// an [`Asset`] at that index, or `Err` otherwise.
    #[inline]
    fn find(&self, id: &I) -> Result<usize, usize>
    where
        I: Ord,
    {
        self.map.binary_search_by(move |a| a.id.cmp(id))
    }

    ///
    #[inline]
    fn get_value(&self, id: &I) -> Option<&V>
    where
        I: Ord,
    {
        self.find(id).ok().map(move |i| &self.map[i].value)
    }

    /// Returns the total value for assets with the given `id`.
    #[inline]
    pub fn value(&self, id: &I) -> V
    where
        I: Ord,
        V: Clone + Default,
    {
        self.get_value(id).cloned().unwrap_or_default()
    }

    /// Returns `true` if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    pub fn contains(&self, asset: &Asset<I, V>) -> bool
    where
        I: Ord,
        V: Default + PartialOrd,
    {
        if asset.value == Default::default() {
            return true;
        }
        match self.get_value(&asset.id) {
            Some(value) => value >= &asset.value,
            _ => false,
        }
    }

    /// Returns an iterator over the assets in `self`.
    #[inline]
    pub fn iter(&self) -> slice::Iter<Asset<I, V>> {
        self.map.iter()
    }

    /// Inserts `asset` into `self` increasing the `AssetValue` at `asset.id`.
    #[inline]
    pub fn deposit(&mut self, asset: Asset<I, V>)
    where
        I: Ord,
        V: AddAssign + Default + PartialEq,
    {
        if asset.value == Default::default() {
            return;
        }
        match self.find(&asset.id) {
            Ok(index) => self.map[index] += asset.value,
            Err(index) => self.map.insert(index, asset),
        }
    }

    /// Sets the value at the `index` to `value` or removes the entry at `index` if `value == 0`.
    #[inline]
    fn set_or_remove(&mut self, index: usize, value: V)
    where
        V: Default + PartialEq,
    {
        if value == Default::default() {
            self.map.remove(index);
        } else {
            self.map[index].value = value;
        }
    }

    /// Tries to remove `asset` from `self` decreasing the `AssetValue` at `asset.id`, returning
    /// `false` if this would overflow. To skip the overflow check, use
    /// [`withdraw_unchecked`](Self::withdraw_unchecked) instead.
    #[inline]
    pub fn withdraw(&mut self, asset: &Asset<I, V>) -> bool
    where
        I: Ord,
        V: Default + PartialEq,
        for<'v> &'v V: CheckedSub<Output = V>,
    {
        if asset.value == Default::default() {
            return true;
        }
        if let Ok(index) = self.find(&asset.id) {
            if let Some(value) = self.map[index].value.checked_sub(&asset.value) {
                self.set_or_remove(index, value);
                return true;
            }
        }
        false
    }

    /// Removes `asset` from `self` decreasing the `AssetValue` at `asset.id`.
    ///
    /// # Panics
    ///
    /// The method panics if removing `asset` would decrease the value of any entry to below zero.
    /// To catch this condition, use [`withdraw`](Self::withdraw) instead.
    #[inline]
    pub fn withdraw_unchecked(&mut self, asset: &Asset<I, V>)
    where
        I: Ord,
        V: Default + PartialEq,
        for<'v> &'v V: Sub<Output = V>,
    {
        if asset.value == Default::default() {
            return;
        }
        match self.find(&asset.id) {
            Ok(index) => self.set_or_remove(index, &self.map[index].value - &asset.value),
            _ => panic!("Trying to subtract from an Asset with zero value."),
        }
    }

    /// Removes all entries in `self` which return `false` after applying `f`.
    #[inline]
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&Asset<I, V>) -> bool,
    {
        self.map.retain(move |asset| f(asset))
    }

    /// Removes all assets from `self`.
    #[inline]
    pub fn clear(&mut self) {
        self.map.clear()
    }

    /// Removes all assets with the given `id`, returning their total value. This method returns
    /// `None` in the case that `id` is not stored in `self`.
    #[inline]
    pub fn remove(&mut self, id: I) -> Option<V>
    where
        I: Ord,
    {
        self.find(&id).ok().map(move |i| self.map.remove(i).value)
    }
}

impl<I, V> AsRef<[Asset<I, V>]> for AssetList<I, V> {
    #[inline]
    fn as_ref(&self) -> &[Asset<I, V>] {
        self.map.as_ref()
    }
}

impl<I, V> Borrow<[Asset<I, V>]> for AssetList<I, V> {
    #[inline]
    fn borrow(&self) -> &[Asset<I, V>] {
        self.map.borrow()
    }
}

impl<I, V> Deref for AssetList<I, V> {
    type Target = [Asset<I, V>];

    #[inline]
    fn deref(&self) -> &[Asset<I, V>] {
        self.map.deref()
    }
}

impl<I, V> From<AssetList<I, V>> for Vec<Asset<I, V>> {
    #[inline]
    fn from(list: AssetList<I, V>) -> Self {
        list.map
    }
}

impl<I, V> From<Vec<Asset<I, V>>> for AssetList<I, V>
where
    I: Ord,
    V: AddAssign + Default + PartialEq,
{
    #[inline]
    fn from(vector: Vec<Asset<I, V>>) -> Self {
        Self::from_iter(iter::once(vector))
    }
}

impl<I, V> FromIterator<(I, V)> for AssetList<I, V>
where
    I: Ord,
    V: AddAssign + Default + PartialEq,
{
    #[inline]
    fn from_iter<A>(iter: A) -> Self
    where
        A: IntoIterator<Item = (I, V)>,
    {
        iter.into_iter()
            .map(move |(id, value)| Asset::new(id, value))
            .collect()
    }
}

impl<I, V> FromIterator<Asset<I, V>> for AssetList<I, V>
where
    I: Ord,
    V: AddAssign + Default + PartialEq,
{
    #[inline]
    fn from_iter<A>(iter: A) -> Self
    where
        A: IntoIterator<Item = Asset<I, V>>,
    {
        let mut list = Self::new();
        iter.into_iter().for_each(|a| list.deposit(a));
        list
    }
}

impl<I, V> FromIterator<AssetList<I, V>> for AssetList<I, V>
where
    I: Ord,
    V: AddAssign + Default + PartialEq,
{
    #[inline]
    fn from_iter<A>(iter: A) -> Self
    where
        A: IntoIterator<Item = AssetList<I, V>>,
    {
        iter.into_iter().map::<Vec<_>, _>(Into::into).collect()
    }
}

impl<I, V> FromIterator<Vec<Asset<I, V>>> for AssetList<I, V>
where
    I: Ord,
    V: AddAssign + Default + PartialEq,
{
    #[inline]
    fn from_iter<A>(iter: A) -> Self
    where
        A: IntoIterator<Item = Vec<Asset<I, V>>>,
    {
        let mut list = Self::new();
        for item in iter {
            for asset in item {
                list.deposit(asset);
            }
        }
        list
    }
}

impl<I, V> IntoIterator for AssetList<I, V> {
    type Item = Asset<I, V>;
    type IntoIter = vec::IntoIter<Asset<I, V>>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter()
    }
}

impl<'a, I, V> IntoIterator for &'a AssetList<I, V> {
    type Item = &'a Asset<I, V>;
    type IntoIter = slice::Iter<'a, Asset<I, V>>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Asset Map
///
/// This trait represents an asset distribution over some [`Key`](Self::Key) type.
///
/// # Warning
///
/// It is possible that keys are repeated, as long as the assets associated to them are different.
pub trait AssetMap<I, V>: Default {
    /// Key Type
    ///
    /// Keys are used to access the underlying asset values.
    type Key;

    /// Returns the sum of all the assets in `self`.
    fn assets(&self) -> AssetList<I, V>;

    /// Selects asset keys which total up to at least `asset` in value.
    fn select(&self, asset: &Asset<I, V>) -> Selection<I, V, Self>;

    /// Returns at most `n` zero assets with the given `id`.
    fn zeroes(&self, n: usize, id: &I) -> Vec<Self::Key>;

    /// Inserts `asset` at the `key` in the map.
    fn insert(&mut self, key: Self::Key, asset: Asset<I, V>);

    /// Inserts all of the assets in `iter`.
    #[inline]
    fn insert_all<A>(&mut self, iter: A)
    where
        A: IntoIterator<Item = (Self::Key, Asset<I, V>)>,
    {
        iter.into_iter()
            .for_each(move |(key, asset)| self.insert(key, asset))
    }

    /// Inserts all of the assets in `iter` using a fixed `id`.
    #[inline]
    fn insert_all_same<A>(&mut self, id: I, iter: A)
    where
        I: Clone,
        A: IntoIterator<Item = (Self::Key, V)>,
    {
        iter.into_iter()
            .for_each(move |(key, value)| self.insert(key, Asset::new(id.clone(), value)));
    }

    /// Inserts all of the assets in `iter` using a fixed `id` and zero value.
    #[inline]
    fn insert_zeroes<A>(&mut self, id: I, iter: A)
    where
        I: Clone,
        V: Default,
        A: IntoIterator<Item = Self::Key>,
    {
        iter.into_iter()
            .for_each(move |key| self.insert(key, Asset::zero(id.clone())));
    }

    /// Tries to remove the `key` from the map, returning `true` if the `key` was stored in the
    /// map and removed.
    fn remove(&mut self, key: Self::Key, asset: Asset<I, V>) -> bool;

    /// Removes all the keys in `iter` from the map.
    fn remove_all<A>(&mut self, iter: A)
    where
        A: IntoIterator<Item = (Self::Key, Asset<I, V>)>,
    {
        for (key, asset) in iter {
            self.remove(key, asset);
        }
    }

    /// Retains the elements from `self` that return `true` after applying `f`.
    fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Self::Key, &mut Vec<Asset<I, V>>) -> bool;
}

/// Implements [`AssetMap`] for map types.
macro_rules! impl_asset_map_for_maps_body {
    ($K:ty, $I:ty, $V:ty, $entry:tt) => {
        type Key = $K;

        #[inline]
        fn assets(&self) -> AssetList<$I, $V> {
            self.iter()
                .flat_map(move |(_, assets)| assets.iter().cloned())
                .collect()
        }

        #[inline]
        fn select(&self, asset: &Asset<$I, $V>) -> Selection<$I, $V, Self> {
            if asset.value == Default::default() {
                return Selection::default();
            }
            let mut sum = Asset::<$I, $V>::zero(asset.id.clone());
            let mut values = Vec::new();
            let mut min_max_asset = Option::<(&$K, &$V)>::None;
            let map = self
                .iter()
                .map(|(key, assets)| assets.iter().map(move |asset| (key, asset)))
                .flatten()
                .filter_map(|(key, item)| {
                    if item.value != Default::default() && item.id == asset.id {
                        Some((key, &item.value))
                    } else {
                        None
                    }
                });
            for (key, value) in map {
                if value > &asset.value {
                    min_max_asset = Some(match min_max_asset.take() {
                        Some(best) if value >= &best.1 => best,
                        _ => (key, value),
                    });
                } else if value == &asset.value {
                    return Selection::new(Default::default(), vec![(key.clone(), value.clone())]);
                } else {
                    sum.value.add_assign(value);
                    values.push((key.clone(), value.clone()));
                }
            }
            if let Some((best_key, best_value)) = min_max_asset {
                return Selection::new(
                    best_value - &asset.value,
                    vec![(best_key.clone(), best_value.clone())],
                );
            }
            if sum.value < asset.value {
                Selection::default()
            } else {
                Selection::new(&sum.value - &asset.value, values)
            }
        }

        #[inline]
        fn zeroes(&self, n: usize, id: &$I) -> Vec<Self::Key> {
            self.iter()
                .filter_map(move |(key, assets)| {
                    assets
                        .iter()
                        .any(move |a| &a.id == id && a.value == Default::default())
                        .then(move || key.clone())
                })
                .take(n)
                .collect()
        }

        #[inline]
        fn insert(&mut self, key: Self::Key, asset: Asset<$I, $V>) {
            match self.entry(key) {
                $entry::Vacant(entry) => {
                    entry.insert(vec![asset]);
                }
                $entry::Occupied(mut entry) => {
                    let assets = entry.get_mut();
                    if let Err(index) = assets.binary_search(&asset) {
                        assets.insert(index, asset);
                    }
                }
            }
        }

        #[inline]
        fn remove(&mut self, key: Self::Key, asset: Asset<$I, $V>) -> bool {
            if let $entry::Occupied(mut entry) = self.entry(key) {
                let assets = entry.get_mut();
                if let Ok(index) = assets.binary_search(&asset) {
                    assets.remove(index);
                    if assets.is_empty() {
                        entry.remove();
                    }
                    return true;
                }
            }
            false
        }

        #[inline]
        fn retain<F>(&mut self, mut f: F)
        where
            F: FnMut(&Self::Key, &mut Vec<Asset<$I, $V>>) -> bool,
        {
            self.retain(move |key, assets| f(key, assets));
        }
    };
}

/// B-Tree Map [`AssetMap`] Implementation
pub type BTreeAssetMap<K, I, V> = BTreeMap<K, Vec<Asset<I, V>>>;

impl<K, I, V> AssetMap<I, V> for BTreeAssetMap<K, I, V>
where
    K: Clone + Ord,
    I: Clone + Ord,
    V: AddAssign + Clone + Default + Ord + Sub<Output = V> + for<'v> AddAssign<&'v V>,
    for<'v> &'v V: Sub<Output = V>,
{
    impl_asset_map_for_maps_body! { K, I, V, BTreeMapEntry }
}

/// Hash Map [`AssetMap`] Implementation
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub type HashAssetMap<K, I, V, S = RandomState> = HashMap<K, Vec<Asset<I, V>>, S>;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<K, I, V, S> AssetMap<I, V> for HashAssetMap<K, I, V, S>
where
    K: Clone + Hash + Eq,
    I: Clone + Ord,
    V: AddAssign + Clone + Default + Ord + Sub<Output = V> + for<'v> AddAssign<&'v V>,
    for<'v> &'v V: Sub<Output = V>,
    S: BuildHasher + Default,
{
    impl_asset_map_for_maps_body! { K, I, V, HashMapEntry }
}

/// Asset Selection
///
/// This `struct` is created by the [`select`](AssetMap::select) method of [`AssetMap`]. See its
/// documentation for more.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "V: Clone, M::Key: Clone"),
    Debug(bound = "V: Debug, M::Key: Debug"),
    Default(bound = "V: Default"),
    Eq(bound = "V: Eq, M::Key: Eq"),
    Hash(bound = "V: Hash, M::Key: Hash"),
    PartialEq(bound = "V: PartialEq, M::Key: PartialEq")
)]
pub struct Selection<I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    /// Change Amount
    pub change: V,

    /// Asset Value Distribution
    pub values: Vec<(M::Key, V)>,
}

impl<I, V, M> Selection<I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    /// Builds a new [`Selection`] from `change` and `values`.
    #[inline]
    pub fn new(change: V, values: Vec<(M::Key, V)>) -> Self {
        Self { change, values }
    }

    /// Returns `true` if `self` is an empty [`Selection`].
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns an iterator over [`self.values`](Self::values) by reference.
    #[inline]
    pub fn iter(&self) -> SelectionIter<I, V, M> {
        SelectionIter::new(self.values.iter())
    }

    /// Returns an iterator over the keys in [`self.values`](Self::values) by reference.
    #[inline]
    pub fn keys(&self) -> SelectionKeys<I, V, M> {
        SelectionKeys::new(self.values.iter().map(move |(key, _)| key))
    }
}

/// [`SelectionIter`] Iterator Type
type SelectionIterType<'s, I, V, M> = slice::Iter<'s, (<M as AssetMap<I, V>>::Key, V)>;

/// Selection Iterator
///
/// This `struct` is created by the [`iter`](Selection::iter) method on [`Selection`].
/// See its documentation for more.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = "V: Debug, M::Key: Debug"))]
pub struct SelectionIter<'s, I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    /// Base Iterator
    iter: SelectionIterType<'s, I, V, M>,
}

impl<'s, I, V, M> SelectionIter<'s, I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    /// Builds a new [`SelectionIter`] from `iter`.
    #[inline]
    fn new(iter: SelectionIterType<'s, I, V, M>) -> Self {
        Self { iter }
    }
}

// TODO: Implement all optimized methods/traits.
impl<'s, I, V, M> Iterator for SelectionIter<'s, I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    type Item = &'s (M::Key, V);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'s, I, V, M> FusedIterator for SelectionIter<'s, I, V, M> where M: AssetMap<I, V> + ?Sized {}

/// [`SelectionKeys`] Map Function Type
type SelectionKeysMapFnType<'s, I, V, M> =
    fn(&'s (<M as AssetMap<I, V>>::Key, V)) -> &'s <M as AssetMap<I, V>>::Key;

/// [`SelectionKeys`] Iterator Type
type SelectionKeysType<'s, I, V, M> =
    iter::Map<SelectionIterType<'s, I, V, M>, SelectionKeysMapFnType<'s, I, V, M>>;

/// Selection Keys Iterator
///
/// This `struct` is created by the [`keys`](Selection::keys) method on [`Selection`].
/// See its documentation for more.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = "V: Debug, M::Key: Debug"))]
pub struct SelectionKeys<'s, I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    /// Base Iterator
    iter: SelectionKeysType<'s, I, V, M>,
}

impl<'s, I, V, M> SelectionKeys<'s, I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    /// Builds a new [`SelectionKeys`] from `iter`.
    #[inline]
    fn new(iter: SelectionKeysType<'s, I, V, M>) -> Self {
        Self { iter }
    }
}

// TODO: Implement all optimized methods/traits.
impl<'s, I, V, M> Iterator for SelectionKeys<'s, I, V, M>
where
    M: AssetMap<I, V> + ?Sized,
{
    type Item = &'s M::Key;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'s, I, V, M> FusedIterator for SelectionKeys<'s, I, V, M> where M: AssetMap<I, V> + ?Sized {}

/// Asset Metadata
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde")
)]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct AssetMetadata {
    /// Number of Decimals
    pub decimals: u32,

    /// Asset Symbol
    pub symbol: String,
}

impl AssetMetadata {
    /// Returns a string formatting of only the `value` interpreted using `self` as the metadata.
    #[inline]
    pub fn display_value<V>(&self, value: V) -> String
    where
        for<'v> &'v V: Div<u128, Output = u128>,
    {
        // TODO: What if we want more than three `FRACTIONAL_DIGITS`? How do we make this method
        //       more general?
        const FRACTIONAL_DIGITS: u32 = 3;
        let value_base_units = &value / (10u128.pow(self.decimals));
        let fractional_digits = &value / (10u128.pow(self.decimals - FRACTIONAL_DIGITS))
            % (10u128.pow(FRACTIONAL_DIGITS));
        format!("{}.{:0>3}", value_base_units, fractional_digits)
    }

    /// Returns a string formatting of `value` interpreted using `self` as the metadata including
    /// the symbol.
    #[inline]
    pub fn display<V>(&self, value: V) -> String
    where
        for<'v> &'v V: Div<u128, Output = u128>,
    {
        format!("{} {}", self.display_value(value), self.symbol)
    }
}

/// Metadata Display
pub trait MetadataDisplay {
    /// Returns a string representation of `self` given the asset `metadata`.
    fn display(&self, metadata: &AssetMetadata) -> String;
}

/// Asset Manager
pub trait AssetManager<I> {
    /// Returns the metadata associated to `id`.
    fn metadata(&self, id: &I) -> Option<&AssetMetadata>;
}

/// Implements [`AssetManager`] for map types.
macro_rules! impl_asset_manager_for_maps_body {
    ($I:ident) => {
        #[inline]
        fn metadata(&self, id: &$I) -> Option<&AssetMetadata> {
            self.get(id)
        }
    };
}

/// B-Tree Map [`AssetManager`] Implementation
pub type BTreeAssetManager<I> = BTreeMap<I, AssetMetadata>;

impl<I> AssetManager<I> for BTreeAssetManager<I>
where
    I: Ord,
{
    impl_asset_manager_for_maps_body! { I }
}

/// Hash Map [`AssetManager`] Implementation
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub type HashAssetManager<I, S = RandomState> = HashMap<I, AssetMetadata, S>;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<I, S> AssetManager<I> for HashAssetManager<I, S>
where
    I: Eq + Hash,
    S: BuildHasher + Default,
{
    impl_asset_manager_for_maps_body! { I }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use manta_crypto::rand::OsRng;

    /// Tests asset conversion into and from bytes.
    #[test]
    fn asset_into_and_from_bytes() {
        let mut rng = OsRng;
        let asset = Asset::gen(&mut rng);
        assert_eq!(asset, Asset::from_bytes(asset.into_bytes()));
        let mut asset_bytes = [0; Asset::SIZE];
        rng.fill_bytes(&mut asset_bytes);
        assert_eq!(asset_bytes, Asset::from_bytes(asset_bytes).into_bytes());
    }

    /// Tests asset arithmetic.
    #[test]
    fn asset_arithmetic() {
        let mut rng = OsRng;
        let mut asset = Asset::zero(rng.gen());
        let value = rng.gen();
        let _ = asset + value;
        asset += value;
        let _ = asset - value;
        asset -= value;
    }
}
