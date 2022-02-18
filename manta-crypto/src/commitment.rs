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

//! Commitment Schemes

use crate::constraint::Native;

/// Commitment Scheme
pub trait CommitmentScheme<COM = ()> {
    /// Randomness Type
    type Randomness;

    /// Input Type
    type Input;

    /// Output Type
    type Output;

    /// Commits to the `input` value using `randomness` inside the `compiler`.
    fn commit_in(
        &self,
        randomness: &Self::Randomness,
        input: &Self::Input,
        compiler: &mut COM,
    ) -> Self::Output;

    /// Commits to the `input` value using `randomness`
    #[inline]
    fn commit(&self, randomness: &Self::Randomness, input: &Self::Input) -> Self::Output
    where
        COM: Native,
    {
        self.commit_in(randomness, input, &mut COM::compiler())
    }
}
