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

//! Random Number Generator Utilities

use core::marker::PhantomData;
use rand_core::{block::BlockRngCore, CryptoRng, Error, RngCore, SeedableRng};

/// Random Number Generator Sized Wrapper
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SizedRng<'r, R>(pub &'r mut R)
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

impl<'r, R> BlockRngCore for SizedRng<'r, R>
where
    R: BlockRngCore + ?Sized,
{
    type Item = R::Item;

    type Results = R::Results;

    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        self.0.generate(results)
    }
}

/// Seed Into Random Number Generator
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

impl<S, R> BlockRngCore for SeedIntoRng<S, R>
where
    R: BlockRngCore,
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
