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

// TODO: Add macro to build `AssetId` and `AssetBalance`.
// TODO: Implement all `rand` sampling traits.
// TODO: Should we rename `AssetBalance` to `AssetValue` to be more consistent?
// TODO: Implement `Concat` for `AssetId` and `AssetBalance`.
// TODO: Add implementations for `AssetMap` using key-value maps like `BTreeMap` and `HashMap`

use alloc::vec::Vec;
use core::{
    convert::TryFrom,
    fmt::Debug,
    hash::Hash,
    iter::{FusedIterator, Sum},
    ops::{Add, AddAssign, Mul, Sub, SubAssign},
};
use derive_more::{
    Add, AddAssign, Display, Div, DivAssign, From, Mul, MulAssign, Product, Sub, SubAssign, Sum,
};
use manta_crypto::constraint::{
    reflection::{unknown, HasAllocation, HasVariable, Var},
    Allocation, PublicOrSecret, Secret, Variable,
};
use manta_util::{array_map, fallible_array_map, into_array_unchecked, Concat, ConcatAccumulator};
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};

/// [`AssetId`] Base Type
type AssetIdType = u32;

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
    /// [`AssetBalance`].
    #[inline]
    pub const fn with(self, value: AssetBalance) -> Asset {
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

impl Distribution<AssetId> for Standard {
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> AssetId {
        AssetId(self.sample(rng))
    }
}

impl From<AssetId> for [u8; AssetId::SIZE] {
    #[inline]
    fn from(entry: AssetId) -> Self {
        entry.into_bytes()
    }
}

/// [`AssetBalance`] Base Type
type AssetBalanceType = u128;

/// Asset Balance Type
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
pub struct AssetBalance(
    /// [`Asset`] Balance
    pub AssetBalanceType,
);

impl AssetBalance {
    /// The size of this type in bits.
    pub const BITS: u32 = AssetBalanceType::BITS;

    /// The size of this type in bytes.
    pub const SIZE: usize = (Self::BITS / 8) as usize;

    /// Constructs a new [`Asset`] with `self` as the [`AssetBalance`] and `id` as the [`AssetId`].
    #[inline]
    pub const fn with(self, id: AssetId) -> Asset {
        Asset::new(id, self)
    }

    /// Converts a byte array into `self`.
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(AssetBalanceType::from_le_bytes(bytes))
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

impl Distribution<AssetBalance> for Standard {
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> AssetBalance {
        AssetBalance(self.sample(rng))
    }
}

impl From<AssetBalance> for [u8; AssetBalance::SIZE] {
    #[inline]
    fn from(entry: AssetBalance) -> Self {
        entry.into_bytes()
    }
}

impl Mul<AssetBalance> for AssetBalanceType {
    type Output = AssetBalanceType;

    #[inline]
    fn mul(self, rhs: AssetBalance) -> Self::Output {
        self * rhs.0
    }
}

impl<'a> Sum<&'a AssetBalance> for AssetBalance {
    #[inline]
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a AssetBalance>,
    {
        iter.copied().sum()
    }
}

/// [`AssetBalance`] Array Type
pub type AssetBalances<const N: usize> = [AssetBalance; N];

/// Samples asset balances from `rng`.
#[inline]
pub(crate) fn sample_asset_balances<R, const N: usize>(rng: &mut R) -> AssetBalances<N>
where
    R: RngCore + ?Sized,
{
    // FIXME: We have to use this implementation because of a bug in `rand`.
    //        See `https://github.com/rust-random/rand/pull/1173`.
    into_array_unchecked(rng.sample_iter(Standard).take(N).collect::<Vec<_>>())
}

/// Change Iterator
///
/// An iterator over [`AssetBalance`] change amounts.
///
/// This `struct` is created by the [`make_change`](AssetBalance::make_change) method on
/// [`AssetBalance`]. See its documentation for more.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Change {
    /// Base Amount
    base: AssetBalanceType,

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
    const fn new(amount: AssetBalanceType, n: usize) -> Option<Self> {
        let n_div = n as AssetBalanceType;
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
    type Item = AssetBalance;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.units {
            return None;
        }
        let amount = self.base + (self.index < self.remainder) as u128;
        self.index += 1;
        Some(AssetBalance(amount))
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
    pub value: AssetBalance,
}

impl Asset {
    /// The size of the data in this type in bits.
    pub const BITS: u32 = AssetId::BITS + AssetBalance::BITS;

    /// The size of the data in this type in bytes.
    pub const SIZE: usize = (Self::BITS / 8) as usize;

    /// Builds a new [`Asset`] from an `id` and a `value`.
    #[inline]
    pub const fn new(id: AssetId, value: AssetBalance) -> Self {
        Self { id, value }
    }

    /// Builds a new zero [`Asset`] with the given `id`.
    #[inline]
    pub const fn zero(id: AssetId) -> Self {
        Self::new(id, AssetBalance(0))
    }

    /// Builds a new [`Asset`] from an existing one with a new `value`.
    #[inline]
    pub const fn with_value(&self, value: AssetBalance) -> Self {
        Self::new(self.id, value)
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
            AssetBalance::from_bytes(into_array_unchecked(&bytes[split..])),
        )
    }

    /// Converts `self` into a byte array.
    #[inline]
    pub fn into_bytes(self) -> [u8; Self::SIZE] {
        into_array_unchecked(self.accumulated::<Vec<_>>())
    }
}

impl Add<AssetBalance> for Asset {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: AssetBalance) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign<AssetBalance> for Asset {
    #[inline]
    fn add_assign(&mut self, rhs: AssetBalance) {
        self.value += rhs;
    }
}

impl Sub<AssetBalance> for Asset {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: AssetBalance) -> Self::Output {
        self -= rhs;
        self
    }
}

impl SubAssign<AssetBalance> for Asset {
    #[inline]
    fn sub_assign(&mut self, rhs: AssetBalance) {
        self.value -= rhs;
    }
}

impl Concat for Asset {
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        accumulator.extend(&self.id.into_bytes());
        accumulator.extend(&self.value.into_bytes());
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

impl From<Asset> for (AssetId, AssetBalance) {
    #[inline]
    fn from(asset: Asset) -> Self {
        (asset.id, asset.value)
    }
}

impl Distribution<Asset> for Standard {
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> Asset {
        Asset::new(self.sample(rng), self.sample(rng))
    }
}

/// Asset Id Variable
pub type AssetIdVar<C> = Var<AssetId, C>;

/// Asset Balance Variable
pub type AssetBalanceVar<C> = Var<AssetBalance, C>;

/// Asset Variable
pub struct AssetVar<C>
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetBalance, Mode = PublicOrSecret>
        + ?Sized,
{
    /// Asset Id
    pub id: AssetIdVar<C>,

    /// Asset Value
    pub value: AssetBalanceVar<C>,
}

impl<C> AssetVar<C>
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetBalance, Mode = PublicOrSecret>
        + ?Sized,
{
    /// Builds a new [`AssetVar`] from an `id` and a `value`.
    #[inline]
    pub fn new(id: AssetIdVar<C>, value: AssetBalanceVar<C>) -> Self {
        Self { id, value }
    }
}

impl<C> Concat for AssetVar<C>
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetBalance, Mode = PublicOrSecret>
        + ?Sized,
    AssetIdVar<C>: Concat,
    AssetBalanceVar<C>: Concat<Item = <AssetIdVar<C> as Concat>::Item>,
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
        + HasVariable<AssetBalance, Mode = PublicOrSecret>
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
                unknown::<AssetBalance, _>(cs, mode.into()),
            ),
        }
    }
}

impl<C> HasAllocation<C> for Asset
where
    C: HasVariable<AssetId, Mode = PublicOrSecret>
        + HasVariable<AssetBalance, Mode = PublicOrSecret>
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
    pub values: [AssetBalance; N],
}

impl<const N: usize> AssetCollection<N> {
    /// Generates a collection of assets with matching [`AssetId`].
    #[inline]
    pub const fn new(id: AssetId, values: [AssetBalance; N]) -> Self {
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
                Some(id) => {
                    if id == asset.id {
                        Ok(asset.value)
                    } else {
                        Err(counter)
                    }
                }
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
pub trait AssetMap {
    /// Key Type
    ///
    /// Keys are used to access the underlying asset balances. See [`withdraw`](Self::withdraw)
    /// and [`deposit`](Self::deposit) for uses of the [`Key`](Self::Key) type.
    type Key;

    /// Asset Selection Iterator Type
    ///
    /// This type is returned by [`select`](Self::select) when looking for assets in the map.
    type Selection: Iterator<Item = (Self::Key, AssetBalance)>;

    /// Asset Iterator Type
    ///
    /// This type is returned by [`iter`](Self::iter) when iterating over all assets.
    type Iter: Iterator<Item = (Self::Key, Asset)>;

    /// Selects asset keys which total up to at least `asset` in value.
    ///
    /// See [`iter`](Self::iter) for iterating over all the assets in the map instead of a specific
    /// subset summing to the `asset` total.
    fn select(&self, asset: Asset) -> AssetSelection<Self>;

    /// Returns an iterator over all the assets stored in the map.
    ///
    /// See [`select`](Self::select) for selecting an asset distribution that sums to some known
    /// `asset` total.
    fn iter(&self) -> Self::Iter;

    /// Withdraws the asset stored at `key`.
    fn withdraw(&mut self, key: Self::Key);

    /// Deposits `asset` at the key stored at `kind` and `index`, returning `false` if the `key`
    /// was already assigned to some other [`Asset`].
    fn deposit(&mut self, key: Self::Key, asset: Asset) -> bool;

    /// Returns the current balance associated with this `id`.
    #[inline]
    fn balance(&self, id: AssetId) -> AssetBalance {
        self.iter()
            .filter_map(move |(_, asset)| (asset.id == id).then(move || asset.value))
            .sum()
    }

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    fn contains(&self, asset: Asset) -> bool {
        self.balance(asset.id) >= asset.value
    }
}

/// Asset Selection
///
/// This `struct` is generated by the [`select`](AssetMap::select) method of [`AssetMap`]. See its
/// documentation for more.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "M::Selection: Clone"),
    Copy(bound = "M::Selection: Copy"),
    Debug(bound = "M::Selection: Debug"),
    Default(bound = "M::Selection: Default"),
    Eq(bound = "M::Selection: Eq"),
    Hash(bound = "M::Selection: Hash"),
    PartialEq(bound = "M::Selection: PartialEq")
)]
pub struct AssetSelection<M>
where
    M: AssetMap + ?Sized,
{
    /// Change Amount
    pub change: AssetBalance,

    /// Asset Distribution
    pub assets: M::Selection,
}

impl<M> AssetSelection<M>
where
    M: AssetMap + ?Sized,
{
    /// Splits [`self.change`](Self::change) into `n` change components.
    #[inline]
    pub fn split_change(&self, n: usize) -> Option<Change> {
        self.change.make_change(n)
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
        let asset = rng.gen::<Asset>();
        assert_eq!(asset, Asset::from_bytes(asset.into_bytes()));
        let mut asset_bytes = [0; Asset::SIZE];
        rng.fill_bytes(&mut asset_bytes);
        assert_eq!(asset_bytes, Asset::from_bytes(asset_bytes).into_bytes());
    }

    /// Tests asset arithmetic.
    #[test]
    fn asset_arithmetic() {
        let mut rng = thread_rng();
        let mut asset = Asset::zero(rng.gen());
        let value = rng.gen::<AssetBalance>();
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
            let amount = AssetBalance(rng.gen_range(0..0xFFFFFF));
            let n = rng.gen_range(1..0xFFFF);
            let change = amount.make_change(n).unwrap().collect::<Vec<_>>();
            assert_eq!(n, change.len());
            assert_eq!(amount, change.into_iter().sum());
        }
    }
}
