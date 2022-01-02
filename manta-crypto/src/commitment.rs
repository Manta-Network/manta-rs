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

pub use crate::util::{Builder, Input};

/// Commitment Scheme
pub trait CommitmentScheme<COM = ()> {
    /// Trapdoor Type
    type Trapdoor;

    /// Input Type
    type Input;

    /// Output Type
    type Output;

    /// Commits to the `input` value using randomness `trapdoor`.
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut COM,
    ) -> Self::Output;

    /// Starts a new [`Builder`] for extended commitments.
    #[inline]
    fn start<'c>(
        &'c self,
        trapdoor: &'c Self::Trapdoor,
    ) -> Builder<'c, Self, Self::Input, Self::Trapdoor>
    where
        Self::Input: Default,
    {
        Builder::new(self, trapdoor)
    }
}

impl<'c, C, I, T> Builder<'c, C, I, T> {
    /// Commits to the input stored in the builder against the given `compiler`.
    #[inline]
    pub fn commit_with_compiler<COM>(self, compiler: &mut COM) -> C::Output
    where
        C: CommitmentScheme<COM, Trapdoor = T, Input = I>,
    {
        self.base.commit(self.args, &self.input, compiler)
    }

    /// Commits to the input stored in the builder.
    #[inline]
    pub fn commit(self) -> C::Output
    where
        C: CommitmentScheme<Trapdoor = T, Input = I>,
    {
        self.commit_with_compiler(&mut ())
    }
}
