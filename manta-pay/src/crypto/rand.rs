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

//! Random Number Generator Wrappers

use crate::crypto::prf::blake2s::Blake2sSeed;
use rand::{CryptoRng, Error, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Cha-Cha 20 RNG Seedable from a Blake2s Seed
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChaCha20RngBlake2sSeedable(ChaCha20Rng);

impl CryptoRng for ChaCha20RngBlake2sSeedable {}

impl RngCore for ChaCha20RngBlake2sSeedable {
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

impl SeedableRng for ChaCha20RngBlake2sSeedable {
    type Seed = Blake2sSeed;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        Self(ChaCha20Rng::from_seed(seed.0))
    }

    #[inline]
    fn seed_from_u64(state: u64) -> Self {
        Self(ChaCha20Rng::seed_from_u64(state))
    }

    #[inline]
    fn from_rng<R: RngCore>(rng: R) -> Result<Self, Error> {
        ChaCha20Rng::from_rng(rng).map(Self)
    }

    #[inline]
    fn from_entropy() -> Self {
        Self(ChaCha20Rng::from_entropy())
    }
}
