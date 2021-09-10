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

use alloc::vec::Vec;
use core::{
    convert::TryFrom,
    fmt::Debug,
    hash::Hash,
    iter::Sum,
    ops::{Add, AddAssign, Mul, Sub, SubAssign},
};
use derive_more::{
    Add, AddAssign, Display, Div, DivAssign, From, Mul, MulAssign, Product, Sub, SubAssign, Sum,
};
use manta_crypto::constraint::{IsVariable, Secret, Var, Variable};
use manta_util::{
    array_map, fallible_array_map, into_array_unchecked, ByteAccumulator, ConcatBytes,
};
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

    /// Converts `self` into a byte array.
    #[inline]
    pub const fn into_bytes(self) -> [u8; Self::SIZE] {
        self.0.to_le_bytes()
    }

    /// Converts a byte array into `self`.
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(AssetIdType::from_le_bytes(bytes))
    }
}

impl Distribution<AssetId> for Standard {
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> AssetId {
        AssetId(rng.gen())
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

    /// Converts `self` into a byte array.
    #[inline]
    pub const fn into_bytes(self) -> [u8; Self::SIZE] {
        self.0.to_le_bytes()
    }

    /// Converts a byte array into `self`.
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(AssetBalanceType::from_le_bytes(bytes))
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
}

impl Distribution<AssetBalance> for Standard {
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> AssetBalance {
        AssetBalance(rng.gen())
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

#[inline]
pub(crate) fn sample_asset_balances<R, const N: usize>(rng: &mut R) -> AssetBalances<N>
where
    R: RngCore + ?Sized,
{
    // FIXME: We have to use this implementation because of a bug in `rand`.
    //        See `https://github.com/rust-random/rand/pull/1173`.
    into_array_unchecked(rng.sample_iter(Standard).take(N).collect::<Vec<_>>())
}

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

    /// Converts `self` into a byte array.
    #[inline]
    pub fn into_bytes(self) -> [u8; Self::SIZE] {
        into_array_unchecked(self.as_bytes::<Vec<_>>())
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

impl ConcatBytes for Asset {
    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ByteAccumulator + ?Sized,
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
        Asset::new(rng.gen(), rng.gen())
    }
}

/// Asset Id Variable
pub type AssetIdVar<P, M> = Variable<AssetId, P, M>;

/// Asset Balance Variable
pub type AssetBalanceVar<P, M> = Variable<AssetBalance, P, M>;

/// Asset Variable
pub struct AssetVar<P>
where
    AssetId: Var<P, Secret>,
    AssetBalance: Var<P, Secret>,
{
    /// Asset Id
    pub id: AssetIdVar<P, Secret>,

    /// Asset Value
    pub value: AssetBalanceVar<P, Secret>,
}

impl<P> IsVariable<P, Secret> for AssetVar<P>
where
    AssetId: Var<P, Secret>,
    AssetBalance: Var<P, Secret>,
{
    type Type = Asset;
}

impl<P> Var<P, Secret> for Asset
where
    AssetId: Var<P, Secret>,
    AssetBalance: Var<P, Secret>,
{
    type Variable = AssetVar<P>;

    #[inline]
    fn as_variable(&self, ps: &mut P, mode: Secret) -> Self::Variable {
        Self::Variable {
            id: self.id.as_variable(ps, mode),
            value: self.value.as_variable(ps, mode),
        }
    }

    #[inline]
    fn unknown(ps: &mut P, mode: Secret) -> Self::Variable {
        Self::Variable {
            id: AssetId::unknown(ps, mode),
            value: AssetBalance::unknown(ps, mode),
        }
    }
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
        array_map(collection.values, move |v| Asset::new(collection.id, v))
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
