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

//! Pseudo-random Permutation implementation

use manta_crypto::permutation::PseudorandomPermutation;

impl<S, const ARITY: usize, COM> PseudorandomPermutation for super::Hasher<S, ARITY, COM>
where
    S: super::Specification<COM>,
{
    type State = [S::Field; ARITY];

    fn permute_in(&self, state: &mut Self::State, compiler: &mut COM) -> Self::State {
        // convert `[S::Field; ARITY]` to `[&S::Field; ARITY]`
        let mut input = state.iter().collect::<Vec<_>>().try_into().unwrap();
        // permute
        let state = self.hash_untruncated(input, compiler);
        // convert `Vec<S::Field>` to `[S::Field; ARITY]`
        state.try_into().unwrap()
    }
}
