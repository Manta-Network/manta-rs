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

//! Commitments

use core::borrow::Borrow;
use rand::RngCore;

/// Commitment Scheme
pub trait CommitmentScheme {
    /// Commitment Randomness Parameter Type
    type Randomness;

    /// Commitment Output Type
    type Output: PartialEq;

    /// Samples random commitment paramters.
    fn setup<R>(rng: &mut R) -> Self
    where
        R: RngCore + ?Sized;

    /// Commits the `input` with the given `randomness` parameter.
    fn commit<I>(&self, input: I, randomness: &Self::Randomness) -> Self::Output
    where
        I: Borrow<[u8]>;

    /// Checks that the `output` matches the commitment of the `input` with the given `randomness`
    /// parameter.
    #[inline]
    fn check_commitment<I>(
        &self,
        input: I,
        randomness: &Self::Randomness,
        output: &Self::Output,
    ) -> bool
    where
        I: Borrow<[u8]>,
    {
        &self.commit(input, randomness) == output.borrow()
    }
}
