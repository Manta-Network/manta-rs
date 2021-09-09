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
    type InputBuffer: Default;

    /// Commitment Randomness Parameter Type
    type Randomness;

    /// Commitment Output Type
    type Output;

    /// Returns a new [`CommitmentBuilder`] to build up a commitment.
    #[inline]
    fn start(&self) -> CommitmentBuilder<Self> {
        CommitmentBuilder::new(self)
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

/// Commitment Builder
pub struct CommitmentBuilder<'c, C>
where
    C: CommitmentScheme + ?Sized,
{
    /// Commitment Scheme
    commitment_scheme: &'c C,

    /// Input Buffer
    input_buffer: C::InputBuffer,
}

impl<'c, C> CommitmentBuilder<'c, C>
where
    C: CommitmentScheme + ?Sized,
{
    /// Returns a new [`CommitmentBuilder`] for this `commitment_scheme`.
    #[inline]
    pub fn new(commitment_scheme: &'c C) -> Self {
        Self {
            commitment_scheme,
            input_buffer: Default::default(),
        }
    }

    /// Updates the builder with new `input`.
    #[inline]
    pub fn update<I>(mut self, input: &I) -> Self
    where
        I: CommitmentInput<C>,
    {
        CommitmentInput::extend(input, &mut self.input_buffer);
        self
    }

    /// Commits to the input stored in the builder with the given `randomness`.
    #[inline]
    pub fn commit(self, randomness: &C::Randomness) -> C::Output {
        self.commitment_scheme.commit(self.input_buffer, randomness)
    }
}
