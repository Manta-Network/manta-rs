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

//! Pseudorandom Function Families

/// Pseudorandom Function Families (PRF) Trait
pub trait PseudorandomFunctionFamily {
    /// PRF Seed Type
    type Seed;

    /// PRF Input Type
    type Input: Default;

    /// PRF Output Type
    type Output;

    /// Evaluates the PRF at the `seed` and `input`.
    fn evaluate(seed: &Self::Seed, input: &Self::Input) -> Self::Output;

    /// Evaluates the PRF at the `seed` with the default input.
    #[inline]
    fn evaluate_zero(seed: &Self::Seed) -> Self::Output {
        Self::evaluate(seed, &Self::Input::default())
    }
}
