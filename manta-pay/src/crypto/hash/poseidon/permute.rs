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

use core::convert::identity;
use manta_crypto::permutation::PseudorandomPermutation;
use manta_util::into_array_unchecked;

impl<S, const ARITY: usize, COM> PseudorandomPermutation for super::Hasher<S, ARITY, COM>
where
    S: super::Specification<COM>,
{
    // width is `ARITY + 1`
    type Domain = [S::Field; ARITY + 1];

    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM) {
        let result = self.hash_untruncated(manta_util::array_map_ref(state, identity), compiler);
        *state = into_array_unchecked(result)
    }
}
