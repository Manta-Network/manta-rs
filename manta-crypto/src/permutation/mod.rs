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

//! Pseudorandom Permutations

pub mod duplex;
pub mod sponge;

/// Pseudorandom Permutation
pub trait PseudorandomPermutation<COM = ()> {
    /// Permutation Domain Type
    ///
    /// A pseudorandom permutation acts on this domain, and should be a bijection on this space.
    type Domain;

    /// Computes the permutation of `state`.
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM);
}

impl<P, COM> PseudorandomPermutation<COM> for &P
where
    P: PseudorandomPermutation<COM>,
{
    type Domain = P::Domain;

    #[inline]
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM) {
        (*self).permute(state, compiler)
    }
}

/// Pseudorandom Permutation Family
pub trait PseudorandomPermutationFamily<COM = ()> {
    /// Key Type
    type Key: ?Sized;

    /// Permutation Domain Type
    ///
    /// A pseudorandom permutation acts on this domain, and should be a bijection on this space.
    type Domain;

    /// Permutation Type
    ///
    /// Given a [`Key`](Self::Key) we can produce a pseudorandom permutation of this type.
    type Permutation: PseudorandomPermutation<COM, Domain = Self::Domain>;

    /// Returns the pseudorandom permutation associated to the given `key`.
    fn permutation(&self, key: &Self::Key, compiler: &mut COM) -> Self::Permutation;

    /// Computes the permutation of `state` under the pseudorandom permutation derived from `key`.
    #[inline]
    fn permute(&self, key: &Self::Key, state: &mut Self::Domain, compiler: &mut COM) {
        self.permutation(key, compiler).permute(state, compiler)
    }
}

impl<P, COM> PseudorandomPermutationFamily<COM> for &P
where
    P: PseudorandomPermutationFamily<COM>,
{
    type Key = P::Key;
    type Domain = P::Domain;
    type Permutation = P::Permutation;

    #[inline]
    fn permutation(&self, key: &Self::Key, compiler: &mut COM) -> Self::Permutation {
        (*self).permutation(key, compiler)
    }
}
