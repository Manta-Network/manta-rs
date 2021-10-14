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

//! Random Number Generators

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, iter::repeat, marker::PhantomData};
use manta_util::into_array_unchecked;

pub use rand_core::{block, CryptoRng, Error, RngCore, SeedableRng};

/// Random Number Generator Sized Wrapper
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SizedRng<'r, R>(
    /// Mutable Reference to Random Number Generator
    pub &'r mut R,
)
where
    R: ?Sized;

impl<'r, R> CryptoRng for SizedRng<'r, R> where R: CryptoRng + ?Sized {}

impl<'r, R> RngCore for SizedRng<'r, R>
where
    R: RngCore + ?Sized,
{
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<'r, R> block::BlockRngCore for SizedRng<'r, R>
where
    R: block::BlockRngCore + ?Sized,
{
    type Item = R::Item;

    type Results = R::Results;

    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        self.0.generate(results)
    }
}

/// Seed Into Random Number Generator
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "R: Clone"),
    Copy(bound = "R: Copy"),
    Debug(bound = "R: Debug"),
    Default(bound = "R: Default"),
    Eq(bound = "R: Eq"),
    Hash(bound = "R: Hash"),
    Ord(bound = "R: Ord"),
    PartialEq(bound = "R: PartialEq"),
    PartialOrd(bound = "R: PartialOrd")
)]
pub struct SeedIntoRng<S, R> {
    /// Inner Rng
    inner: R,

    /// Type Parameter Marker
    __: PhantomData<S>,
}

impl<S, R> SeedIntoRng<S, R> {
    /// Builds a new [`SeedIntoRng`] from an existing `inner` random number generator.
    #[inline]
    fn new(inner: R) -> Self {
        Self {
            inner,
            __: PhantomData,
        }
    }
}

impl<S, R> CryptoRng for SeedIntoRng<S, R> where R: CryptoRng {}

impl<S, R> RngCore for SeedIntoRng<S, R>
where
    R: RngCore,
{
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest)
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl<S, R> block::BlockRngCore for SeedIntoRng<S, R>
where
    R: block::BlockRngCore,
{
    type Item = R::Item;

    type Results = R::Results;

    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        self.inner.generate(results)
    }
}

impl<S, R> SeedableRng for SeedIntoRng<S, R>
where
    S: Into<R::Seed> + Default + AsMut<[u8]>,
    R: SeedableRng,
{
    type Seed = S;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        Self::new(R::from_seed(seed.into()))
    }

    #[inline]
    fn seed_from_u64(state: u64) -> Self {
        Self::new(R::seed_from_u64(state))
    }

    #[inline]
    fn from_rng<T: RngCore>(rng: T) -> Result<Self, Error> {
        R::from_rng(rng).map(Self::new)
    }

    #[cfg(feature = "getrandom")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "getrandom")))]
    #[inline]
    fn from_entropy() -> Self {
        Self::new(R::from_entropy())
    }
}

/// Standard Distribution
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Standard;

/// Sampling Trait
pub trait Sample<D = Standard>: Sized {
    /// Returns a random value of type `Self`, sampled according to the given `distribution`,
    /// generated from the `rng`.
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Returns a random value of type `Self`, sampled according to the default distribution of
    /// type `D`, generated from the `rng`.
    #[inline]
    fn gen<R>(rng: &mut R) -> Self
    where
        D: Default,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::sample(Default::default(), rng)
    }
}

/// Generates [`Sample`] implementation for `$type` using conversion from `u32`.
macro_rules! impl_sample_from_u32 {
    ($($type:tt),+) => {
        $(
            impl Sample for $type {
                #[inline]
                fn sample<R>(distribution: Standard, rng: &mut R) -> Self
                where
                    R: RngCore + ?Sized,
                {
                    let _ = distribution;
                    rng.next_u32() as Self
                }
            }
        )+
    };
}

impl_sample_from_u32! { u8, u16, u32 }

impl Sample for u64 {
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        rng.next_u64()
    }
}

impl Sample for u128 {
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        ((rng.next_u64() as u128) << 64) | (rng.next_u64() as u128)
    }
}

impl<D, T, const N: usize> Sample<D> for [T; N]
where
    D: Clone,
    T: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        into_array_unchecked(
            repeat(distribution)
                .take(N)
                .map(move |d| T::sample(d, rng))
                .collect::<Vec<_>>(),
        )
    }
}

/// Fallible Sampling Trait
pub trait TrySample<D = Standard>: Sized {
    /// Error Type
    type Error;

    /// Tries to return a random value of type `Self`, sampled according to the given
    /// `distribution`, generated from the `rng`.
    fn try_sample<R>(distribution: D, rng: &mut R) -> Result<Self, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Tries to return a random value of type `Self`, sampled according to the default
    /// distribution of type `D`, generated from the `rng`.
    #[inline]
    fn try_gen<R>(rng: &mut R) -> Result<Self, Self::Error>
    where
        D: Default,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::try_sample(Default::default(), rng)
    }
}

/// Random Number Generator
pub trait Rand: CryptoRng + RngCore {
    /// Returns a random value of type `Self`, sampled according to the given `distribution`,
    /// generated from the `rng`.
    #[inline]
    fn sample<D, T>(&mut self, distribution: D) -> T
    where
        T: Sample<D>,
    {
        T::sample(distribution, self)
    }

    /// Tries to return a random value of type `Self`, sampled according to the given
    /// `distribution`, generated from the `rng`.
    #[inline]
    fn try_sample<D, T>(&mut self, distribution: D) -> Result<T, T::Error>
    where
        T: TrySample<D>,
    {
        T::try_sample(distribution, self)
    }

    /// Returns a random value of type `Self`, sampled according to the default distribution of
    /// type `D`, generated from the `rng`.
    #[inline]
    fn gen<D, T>(&mut self) -> T
    where
        D: Default,
        T: Sample<D>,
    {
        T::gen(self)
    }

    /// Tries to return a random value of type `Self`, sampled according to the default
    /// distribution of type `D`, generated from the `rng`.
    #[inline]
    fn try_gen<D, T>(&mut self) -> Result<T, T::Error>
    where
        D: Default,
        T: TrySample<D>,
    {
        T::try_gen(self)
    }
}

impl<R> Rand for R where R: CryptoRng + RngCore + ?Sized {}
