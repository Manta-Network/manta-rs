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

//! Poseidon implementation of sponge

use alloc::vec::Vec;
use manta_crypto::permutation::{
    sponge::{Absorb, Mask, Squeeze},
    PseudorandomPermutation,
};

type Domain<S, COM, const ARITY: usize> =
    <super::Hasher<S, ARITY, COM> as PseudorandomPermutation<COM>>::Domain;

impl<S, const ARITY: usize, COM> Absorb<super::Hasher<S, ARITY, COM>, COM> for Vec<S::Field>
where
    S: super::Specification<COM>,
{
    fn write(&self, state: &mut Domain<S, COM, ARITY>, compiler: &mut COM) {
        assert_eq!(self.len(), ARITY);
        // corresponds to algorithm 2 in page 7 of BDPA11, replacing XOR with ADD
        state.iter_mut().zip(self.iter()).for_each(|(s, c)| {
            S::add_assign(s, c, compiler);
        });
    }
}

impl<S, const ARITY: usize, COM> Squeeze<super::Hasher<S, ARITY, COM>, COM> for Vec<S::Field>
where
    S: super::Specification<COM>,
    S::Field: Clone,
{
    fn read(state: &Domain<S, COM, ARITY>, compiler: &mut COM) -> Self {
        let _ = compiler;
        assert_eq!(state.len(), ARITY);
        state.iter().take(ARITY).cloned().collect()
    }
}

impl<S, const ARITY: usize, COM> Mask<super::Hasher<S, ARITY, COM>, Self, Self, COM>
    for Vec<S::Field>
where
    S: super::Specification<COM>,

    S::Field: Clone,
{
    fn mask(&self, mask: &Self, compiler: &mut COM) -> Self {
        assert_eq!(self.len(), ARITY);
        assert_eq!(mask.len(), ARITY);
        self.iter()
            .zip(mask.iter())
            .map(|(s, m)| S::add(s, m, compiler))
            .collect()
    }

    fn unmask(masked: &Self, mask: &Self, compiler: &mut COM) -> Self {
        assert_eq!(masked.len(), ARITY);
        assert_eq!(mask.len(), ARITY);
        masked
            .iter()
            .zip(mask.iter())
            .map(|(s, m)| S::sub(s, m, compiler))
            .collect()
    }
}
