// Copyright 2019-2021 Manta Network.
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

// TODO: Add macro to build `AssetId` and `AssetValue`.
// TODO: Implement all `rand` sampling traits.
// TODO: Should we rename `AssetValue` to `AssetValue` to be more consistent?
// TODO: Implement `Concat` for `AssetId` and `AssetValue`.
// TODO: Add implementations for `AssetMap` using key-value maps like `BTreeMap` and `HashMap`

use alloc::vec::Vec;
use core::{
    convert::TryFrom,
    fmt::Debug,
    hash::Hash,
    iter,
    iter::{FusedIterator, Sum},
    ops::{Add, AddAssign, Mul, Sub, SubAssign},
    slice,
};
use derive_more::{
    Add, AddAssign, Display, Div, DivAssign, From, Mul, MulAssign, Product, Sub, SubAssign, Sum,
};
use manta_crypto::{
    constraint::{
        reflection::{unknown, HasAllocation, HasVariable, Var},
        Allocation, PublicOrSecret, Secret, Variable,
    },
    rand::{CryptoRng, Rand, RngCore, Sample, Standard},
};
use manta_util::{array_map, fallible_array_map, into_array_unchecked, Concat, ConcatAccumulator};

pub(super) mod prelude {
    #[doc(inline)]
    pub use super::{Asset, AssetId, AssetValue, AssetValues};
}

/// [`AssetId`] Base Type
pub type AssetIdType = u32;

/// Asset Id Type
#[derive(Clone, Copy, Debug, Default, Display, Eq, From, Hash, Ord, PartialEq, PartialOrd)]
#[from(forward)]
pub struct AssetId(
    /// [`Asset`] Id
    pub AssetIdType,
);

impl AssetId {
    /// The size of this type in bits.
    pub const BITS: u32 = AssetIdType::BITS;

    /// The size of this type in bytes.
    pub const SIZE: usize = (Self::BITS / 8) as usize;

    /// Constructs a new [`Asset`] with `self` as the [`AssetId`] and `value` as the
    /// [`AssetValue`].
    #[inline]
    pub const fn with(self, value: AssetValue) -> Asset {
        Asset::new(self, value)
    }

    /// Converts a byte array into `self`.
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(AssetIdType::from_le_bytes(bytes))
    }

    /// Converts `self` into a byte array.
    #[inline]
    pub const fn into_bytes(self) -> [u8; Self::SIZE] {
        self.0.to_le_bytes()
    }
}

impl Concat for AssetId {
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        accumulator.extend(&self.into_bytes());
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(Self::SIZE)
    }
}

impl From<AssetId> for [u8; AssetId::SIZE] {
    #[inline]
    fn from(entry: AssetId) -> Self {
        entry.into_bytes()
    }
}

impl<D> Sample<D> for AssetId
where
    AssetIdType: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

/// [`AssetValue`] Base Type
pub type AssetValueType = u128;

/// Asset Value Type
#[derive(
    Add,
    AddAssign,
    Clone,
    Copy,
    Debug,
    Default,
    Display,
    Div,
    DivAssign,
    Eq,
    From,
    Hash,
    Mul,
    MulAssign,
    Ord,
    PartialEq,
    PartialOrd,
    Product,
    Sub,
    SubAssign,
    Sum,
)]
#[from(forward)]
pub struct AssetValue(
    /// [`Asset`] Value
    pub AssetValueType,
);

impl AssetValue {
    /// The size of this type in bits.
    pub const BITS: u32 = AssetValueType::BITS;

    /// The size of this type in bytes.
    pub const SIZE: usize = (Self::BITS / 8) as usize;

    /// Constructs a new [`Asset`] with `self` as the [`AssetValue`] and `id` as the [`AssetId`].
    #[inline]
    pub const fn with(self, id: AssetId) -> Asset {
        Asset::new(id, self)
    }

    /// Converts a byte array into `self`.
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(AssetValueType::from_le_bytes(bytes))
    }

    /// Converts `self` into a byte array.
    #[inline]
    pub const fn into_bytes(self) -> [u8; Self::SIZE] {
        self.0.to_le_bytes()
    }

    /// Checked integer addition. Computes `self + rhs`, returning `None` if overflow occurred.
    #[inline]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(result) => Some(Self(result)),
            _ => None,
        }
    }

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if overflow occurred.
    #[inline]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(result) => Some(Self(result)),
            _ => None,
        }
    }

    /// Returns an iterator over change amounts in `n` parts.
    #[inline]
    pub const fn make_change(self, n: usize) -> Option<Change> {
        Change::new(self.0, n)
    }
}

impl Concat for AssetValue {
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        accumulator.extend(&self.into_bytes());
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(Self::SIZE)
    }
}

impl From<AssetValue> for [u8; AssetValue::SIZE] {
    #[inline]
    fn from(entry: AssetValue) -> Self {
        entry.into_bytes()
    }
}

impl Mul<AssetValue> for AssetValueType {
    type Output = AssetValueType;

    #[inline]
    fn mul(self, rhs: AssetValue) -> Self::Output {
        self * rhs.0
    }
}

impl<D> Sample<D> for AssetValue
where
    AssetValueType: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self(rng.sample(distribution))
    }
}

impl<'a> Sum<&'a AssetValue> for AssetValue {
    #[inline]
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a AssetValue>,
    {
        iter.copied().sum()
    }
}

/// [`AssetValue`] Array Type
pub type AssetValues<const N: usize> = [AssetValue; N];

/// Change Iterator
///
/// An iterator over [`AssetValue`] change amounts.
///
/// This `struct` is created by the [`make_change`](AssetValue::make_change) method on
/// [`AssetValue`]. See its documentation for more.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Change {
    /// Base Amount
    base: AssetValueType,

    /// Remainder to be Divided
    remainder: usize,

    /// Total Number of Units
    units: usize,

    /// Current Index
    index: usize,
}

impl Change {
    /// Builds a new [`Change`] iterator for `amount` into `n` pieces.
    #[inline]
    const fn new(amount: AssetValueType, n: usize) -> Option<Self> {
        let n_div = n as AssetValueType;
        match amount.checked_div(n_div) {
            Some(base) => Some(Self {
                base,
                remainder: (amount % n_div) as usize,
                units: n,
                index: 0,
            }),
            _ => None,
        }
    }
}

impl Iterator for Change {
    type Item = AssetValue;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.units {
            return None;
        }
        let amount = self.base + (self.index < self.remainder) as u128;
        self.index += 1;
        Some(AssetValue(amount))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.units - self.index;
        (len, Some(len))
    }
}

impl ExactSizeIterator for Change {}

impl FusedIterator for Change {}

/// Asset
#[derive(Clone, Copy, Debug, Default, Display, Eq, From, Hash, PartialEq)]
#[display(fmt = "{{id: {}, value: {}}}", id, value)]
pub struct Asset {
    /// Asset Id
    pub id: AssetId,

    /// Asset Value
    pub value: AssetValue,
}

impl Asset {
    /// The size of the data in this type in bits.
    pub const BITS: u32 = AssetId::BITS + AssetValue::BITS;

    /// The size of the data in this type in bytes.
    pub const SIZE: usize = (Self::BITS / 8) as usize;

    /// Builds a new [`Asset`] from an `id` and a `value`.
    #[inline]
    pub const fn new(id: AssetId, value: AssetValue) -> Self {
        Self { id, value }
    }

    /// Builds a new zero [`Asset`] with the given `id`.
    #[inline]
    pub const fn zero(id: AssetId) -> Self {
        Self::new(id, AssetValue(0))
    }

    /// Returns `true` if `self` is a zero [`Asset`] of some [`AssetId`].
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.value.0 == 0
    }

    /// Checks if the `rhs` asset has the same [`AssetId`].
    #[inline]
    pub const fn same_id(&self, rhs: &Self) -> bool {
        self.id.0 == rhs.id.0
    }

    /// Converts a byte array into `self`.
    #[inline]
    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let split = (AssetId::BITS / 8) as usize;
        Self::new(
            AssetId::from_bytes(into_array_unchecked(&bytes[..split])),
            AssetValue::from_bytes(into_array_unchecked(&bytes[split..])),
        )
    }

    /// Converts `self` into a byte array.
    #[inline]
    pub fn into_bytes(self) -> [u8; Self::SIZE] {
        into_array_unchecked(self.accumulated::<Vec<_>>())
    }

    /// Returns [`self.value`](Self::value) if the given `id` matches [`self.id`](Self::id).
    #[inline]
    pub const fn value_of(&self, id: AssetId) -> Option<AssetValue> {
        if self.id.0 == id.0 {
            Some(self.value)
        } else {
            None
        }
    }

    /// Returns a mutable reference to [`self.value`](Self::value) if the given `id` matches
    /// [`self.id`](Self::id).
    #[inline]
    pub fn value_of_mut(&mut self, id: AssetId) -> Option<&mut AssetValue> {
        if self.id.0 == id.0 {
            Some(&mut self.value)
        } else {
            None
        }
    }
}

impl Add<AssetValue> for Asset {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: AssetValue) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign<AssetValue> for Asset {
    #[inline]
    fn add_assign(&mut self, rhs: AssetValue) {
        self.value += rhs;
    }
}

impl Concat for Asset {
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        self.id.concat(accumulator);
        self.value.concat(accumulator);
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(Self::SIZE)
    }
}

impl From<[u8; Self::SIZE]> for Asset {
    #[inline]
    fn from(array: [u8; Self::SIZE]) -> Self {
        Self::from_bytes(array)
    }
}

impl From<Asset> for [u8; Asset::SIZE] {
    #[inline]
    fn from(entry: Asset) -> Self {
        entry.into_bytes()
    }
}

impl From<Asset> for (AssetId, AssetValue) {
    #[inline]
    fn from(asset: Asset) -> Self {
        (asset.id, asset.value)
    }
}

impl Sample for Asset {
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        Self::new(rng.gen(), rng.gen())
    }
}

impl Sub<AssetValue> for Asset {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: AssetValue) -> Self::Output {
        self -= rhs;
        self
    }
}

impl SubAssign<AssetValue> for Asset {
    #[inline]
    fn sub_assign(&mut self, rhs: AssetValue) {
        self.value -= rhs;
    }
}

/// Asset Id Variable
pub type AssetIdVar<C> = Var<AssetId, C>;

/// Asset Value Variable
pub type AssetValueVar<C> = Var<AssetValue, C>;

/// Asset Variable
pub struct AssetVar<C>
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Mode = PublicOrSecret>
        + ?Sized,
{
    /// Asset Id
    pub id: AssetIdVar<C>,

    /// Asset Value
    pub value: AssetValueVar<C>,
}

impl<C> AssetVar<C>
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Mode = PublicOrSecret>
        + ?Sized,
{
    /// Builds a new [`AssetVar`] from an `id` and a `value`.
    #[inline]
    pub fn new(id: AssetIdVar<C>, value: AssetValueVar<C>) -> Self {
        Self { id, value }
    }
}

impl<C> Concat for AssetVar<C>
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Mode = PublicOrSecret>
        + ?Sized,
    AssetIdVar<C>: Concat,
    AssetValueVar<C>: Concat<Item = <AssetIdVar<C> as Concat>::Item>,
{
    type Item = <AssetIdVar<C> as Concat>::Item;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        self.id.concat(accumulator);
        self.value.concat(accumulator);
    }
}

impl<C> Variable<C> for AssetVar<C>
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Mode = PublicOrSecret>
        + ?Sized,
{
    type Type = Asset;

    type Mode = Secret;

    #[inline]
    fn new(cs: &mut C, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self::new(
                cs.new_known_allocation(&this.id, mode),
                cs.new_known_allocation(&this.value, mode),
            ),
            Allocation::Unknown(mode) => Self::new(
                unknown::<AssetId, _>(cs, mode.into()),
                unknown::<AssetValue, _>(cs, mode.into()),
            ),
        }
    }
}

impl<C> HasAllocation<C> for Asset
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetValue, Mode = PublicOrSecret>
        + ?Sized,
{
    type Variable = AssetVar<C>;
    type Mode = Secret;
}

/// Asset Collection
#[derive(Clone, Copy, Debug, Eq, From, Hash, Ord, PartialEq, PartialOrd)]
#[from(forward)]
pub struct AssetCollection<const N: usize> {
    /// Asset Id
    pub id: AssetId,

    /// Asset Values
    pub values: [AssetValue; N],
}

impl<const N: usize> AssetCollection<N> {
    /// Generates a collection of assets with matching [`AssetId`].
    #[inline]
    pub const fn new(id: AssetId, values: [AssetValue; N]) -> Self {
        Self { id, values }
    }
}

impl<const N: usize> Default for AssetCollection<N> {
    #[inline]
    fn default() -> Self {
        Self::new(Default::default(), [Default::default(); N])
    }
}

impl<const N: usize> From<AssetCollection<N>> for [Asset; N] {
    #[inline]
    fn from(collection: AssetCollection<N>) -> Self {
        array_map(collection.values, move |v| collection.id.with(v))
    }
}

impl<const N: usize> TryFrom<[Asset; N]> for AssetCollection<N> {
    type Error = usize;

    #[inline]
    fn try_from(array: [Asset; N]) -> Result<Self, Self::Error> {
        let mut counter: usize = 0;
        let mut base_id = None;
        let values = fallible_array_map(array, move |asset| {
            let result = match base_id {
                Some(id) if id == asset.id => Ok(asset.value),
                Some(_) => Err(counter),
                _ => {
                    base_id = Some(asset.id);
                    Ok(asset.value)
                }
            };
            counter += 1;
            result
        })?;
        match base_id {
            Some(id) => Ok(Self::new(id, values)),
            _ => Err(0),
        }
    }
}

/// Asset Map
///
/// This trait represents an asset distribution over some [`Key`](Self::Key) type.
pub trait AssetMap: Default {
    /// Key Type
    ///
    /// Keys are used to access the underlying asset values.
    type Key;

    // TODO: Turn `select` and `zeroes` back into iterator returning methods.

    /// Selects asset keys which total up to at least `asset` in value.
    fn select(&self, asset: Asset) -> Selection<Self>;

    /// Returns at most `n` zero assets with the given `id`.
    fn zeroes(&self, n: usize, id: AssetId) -> Vec<Self::Key>;

    /// Inserts `asset` at the `key` in the map.
    fn insert(&mut self, key: Self::Key, asset: Asset);

    /// Inserts all of the assets in `iter`.
    #[inline]
    fn insert_all<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (Self::Key, Asset)>,
    {
        iter.into_iter()
            .for_each(move |(key, asset)| self.insert(key, asset))
    }

    /// Inserts all of the assets in `iter` using a fixed `id`.
    #[inline]
    fn insert_all_same<I>(&mut self, id: AssetId, iter: I)
    where
        I: IntoIterator<Item = (Self::Key, AssetValue)>,
    {
        iter.into_iter()
            .for_each(move |(key, value)| self.insert(key, id.with(value)));
    }

    /// Inserts all of the assets in `iter` using a fixed `id` and zero value.
    #[inline]
    fn insert_zeroes<I>(&mut self, id: AssetId, iter: I)
    where
        I: IntoIterator<Item = Self::Key>,
    {
        iter.into_iter()
            .for_each(move |key| self.insert(key, Asset::zero(id)));
    }

    /// Removes the `key` from the map.
    fn remove(&mut self, key: Self::Key);

    /// Removes all the keys in `iter` from the map.
    fn remove_all<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Self::Key>,
    {
        iter.into_iter().for_each(move |key| self.remove(key));
    }
}

/// Asset Selection
///
/// This `struct` is created by the [`select`](AssetMap::select) method of [`AssetMap`]. See its
/// documentation for more.
pub struct Selection<M>
where
    M: AssetMap + ?Sized,
{
    /// Change Amount
    pub change: AssetValue,

    /// Asset Value Distribution
    pub values: Vec<(M::Key, AssetValue)>,
}

impl<M> Selection<M>
where
    M: AssetMap + ?Sized,
{
    /// Returns `true` if `self` is an empty [`Selection`].
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns an iterator over [`self.values`](Self::values) by reference.
    #[inline]
    pub fn iter(&self) -> SelectionIter<M> {
        SelectionIter::new(self.values.iter())
    }

    /// Returns an iterator over the keys in [`self.values`](Self::values) by reference.
    #[inline]
    pub fn keys(&self) -> SelectionKeys<M> {
        SelectionKeys::new(self.values.iter().map(move |(key, _)| key))
    }
}

/// [`SelectionIter`] Iterator Type
type SelectionIterType<'s, M> = slice::Iter<'s, (<M as AssetMap>::Key, AssetValue)>;

/// Selection Iterator
///
/// This `struct` is created by the [`iter`](Selection::iter) method on [`Selection`].
/// See its documentation for more.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = "M::Key: Debug"))]
pub struct SelectionIter<'s, M>
where
    M: AssetMap + ?Sized,
{
    /// Base Iterator
    iter: SelectionIterType<'s, M>,
}

impl<'s, M> SelectionIter<'s, M>
where
    M: AssetMap + ?Sized,
{
    /// Builds a new [`SelectionIter`] from `iter`.
    #[inline]
    fn new(iter: SelectionIterType<'s, M>) -> Self {
        Self { iter }
    }
}

// TODO: Implement all optimized methods/traits.
impl<'s, M> Iterator for SelectionIter<'s, M>
where
    M: AssetMap + ?Sized,
{
    type Item = &'s (M::Key, AssetValue);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

/// [`SelectionKeys`] Map Function Type
type SelectionKeysMapFnType<'s, M> =
    fn(&'s (<M as AssetMap>::Key, AssetValue)) -> &'s <M as AssetMap>::Key;

/// [`SelectionKeys`] Iterator Type
type SelectionKeysType<'s, M> = iter::Map<SelectionIterType<'s, M>, SelectionKeysMapFnType<'s, M>>;

/// Selection Keys Iterator
///
/// This `struct` is created by the [`keys`](Selection::keys) method on [`Selection`].
/// See its documentation for more.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = "M::Key: Debug"))]
pub struct SelectionKeys<'s, M>
where
    M: AssetMap + ?Sized,
{
    /// Base Iterator
    iter: SelectionKeysType<'s, M>,
}

impl<'s, M> SelectionKeys<'s, M>
where
    M: AssetMap + ?Sized,
{
    /// Builds a new [`SelectionKeys`] from `iter`.
    #[inline]
    fn new(iter: SelectionKeysType<'s, M>) -> Self {
        Self { iter }
    }
}

// TODO: Implement all optimized methods/traits.
impl<'s, M> Iterator for SelectionKeys<'s, M>
where
    M: AssetMap + ?Sized,
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

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use rand::{thread_rng, Rng};

    /// Tests asset conversion into and from bytes.
    #[test]
    fn asset_into_and_from_bytes() {
        let mut rng = thread_rng();
        let asset = Asset::gen(&mut rng);
        assert_eq!(asset, Asset::from_bytes(asset.into_bytes()));
        let mut asset_bytes = [0; Asset::SIZE];
        rng.fill_bytes(&mut asset_bytes);
        assert_eq!(asset_bytes, Asset::from_bytes(asset_bytes).into_bytes());
    }

    /// Tests asset arithmetic.
    #[test]
    fn asset_arithmetic() {
        let mut rng = thread_rng();
        let mut asset = Asset::zero(AssetId::gen(&mut rng));
        let value = AssetValue::gen(&mut rng);
        let _ = asset + value;
        asset += value;
        let _ = asset - value;
        asset -= value;
    }

    /// Tests that the [`Change`] iterator makes the correct change.
    #[test]
    fn test_change_iterator() {
        let mut rng = thread_rng();
        for _ in 0..0xFFF {
            let amount = AssetValue(rng.gen_range(0..0xFFFF_FFFF));
            let n = rng.gen_range(1..0xFFFF);
            let change = amount.make_change(n).unwrap().collect::<Vec<_>>();
            assert_eq!(n, change.len());
            assert_eq!(amount, change.into_iter().sum());
        }
    }
}
