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

use alloc::vec::Vec;
use manta_crypto::permutation::PseudorandomPermutation;

impl<S, const ARITY: usize, COM> PseudorandomPermutation<COM> for super::Hasher<S, ARITY, COM>
where
    S: super::Specification<COM>,
{
    // domain length is `ARITY + 1`
    type Domain = Vec<S::Field>;

    #[inline]
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM) {
        // first round
        for (i, point) in state.iter_mut().enumerate() {
            let mut elem = S::add_const(point, &self.additive_round_keys[i], compiler);
            S::apply_sbox(&mut elem, compiler);
            *point = elem;
        }
        for round in 1..Self::HALF_FULL_ROUNDS {
            self.full_round(round, state, compiler);
        }
        for round in Self::HALF_FULL_ROUNDS..(Self::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS) {
            self.partial_round(round, state, compiler);
        }
        for round in
            (Self::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS)..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
        {
            self.full_round(round, state, compiler);
        }
    }
}
