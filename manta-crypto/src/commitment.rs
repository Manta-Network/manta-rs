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

//! Commitment Schemes

/// Commitment Scheme
pub trait CommitmentScheme {
    /// Commitment Input Buffer Type
    type InputBuffer;

    /// Commitment Randomness Parameter Type
    type Randomness;

    /// Commitment Output Type
    type Output;

    /// Returns a new [`InputBuffer`](Self::InputBuffer) for building commitments.
    #[must_use = "the input buffer is the only way to build a commitment"]
    fn start(&self) -> Self::InputBuffer;

    /// Updates the `buffer` with `input`.
    #[inline]
    fn update<I>(&self, buffer: &mut Self::InputBuffer, input: &I) -> &Self
    where
        I: CommitmentInput<Self>,
    {
        CommitmentInput::extend(input, buffer);
        self
    }

    /// Commits the `input` buffer with the given `randomness` parameter.
    fn commit(&self, input: Self::InputBuffer, randomness: &Self::Randomness) -> Self::Output;
}

/// Commitment Input
pub trait CommitmentInput<C>
where
    C: CommitmentScheme + ?Sized,
{
    /// Extends the input buffer.
    fn extend(&self, buffer: &mut C::InputBuffer);
}
