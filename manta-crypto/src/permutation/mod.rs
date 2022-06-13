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

//! Permutation and Sponge Crypto Primitives

use crate::constraint::Native;

pub mod sponge;

/// Pseudo-random Permutation
pub trait PseudorandomPermutation<COM = ()> {
    /// State where the permutation is applied
    type State;

    /// Permutes the state in the given `compiler`
    fn permute_in(&self, state: &Self::State, compiler: &mut COM) -> Self::State;

    /// Permutes the state in the native compiler.
    #[inline]
    fn permute(&self, state: &Self::State) -> Self::State
    where
        COM: Native,
    {
        self.permute_in(state, &mut COM::compiler())
    }
}
