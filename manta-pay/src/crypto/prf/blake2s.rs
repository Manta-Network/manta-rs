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

//! Blake2s PRF Implementation

use ark_crypto_primitives::prf::{self, PRF};
use manta_crypto::PseudorandomFunctionFamily;

/// Blake2s Pseudorandom Function Family
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2s;

impl PseudorandomFunctionFamily for Blake2s {
    type Seed = <prf::Blake2s as PRF>::Seed;

    type Input = <prf::Blake2s as PRF>::Input;

    type Output = <prf::Blake2s as PRF>::Output;

    #[inline]
    fn evaluate(seed: &Self::Seed, input: &Self::Input) -> Self::Output {
        prf::Blake2s::evaluate(seed, input).expect("As of arkworks 0.3.0, this never fails.")
    }
}
