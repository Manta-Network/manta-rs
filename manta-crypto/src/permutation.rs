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

/// Sponges over Pseudorandom Permutations
pub mod sponge {
    use super::*;

    /// Permutation Sponge
    ///
    /// This `struct` is a general sponge-like construction which takes a permutation and repeatedly
    /// applies it to an internal state, with read and write access to the state via the [`absorb`]
    /// and [`squeeze`] methods. Using a concrete permutation and fixed [`absorb`] input and
    /// [`squeeze`] output functions one can build the classical sponge constructions.
    ///
    /// [`absorb`]: Self::absorb
    /// [`squeeze`]: Self::squeeze
    pub struct Sponge<'p, P, COM = ()>
    where
        P: PseudorandomPermutation<COM>,
    {
        /// Permutation
        pub permutation: &'p P,

        /// Sponge State
        pub state: &'p mut P::Domain,
    }

    impl<'p, P, COM> Sponge<'p, P, COM>
    where
        P: PseudorandomPermutation<COM>,
    {
        /// Builds a new [`Sponge`] over `permutation` with the given initial `state`.
        #[inline]
        pub fn new(permutation: &'p P, state: &'p mut P::Domain) -> Self {
            Self { permutation, state }
        }

        /// Updates `self` by absorbing writes into the state with `input`.
        #[inline]
        pub fn absorb<A>(&mut self, input: &A, compiler: &mut COM)
        where
            A: Absorb<P, COM>,
        {
            input.write(self.state, compiler);
            self.permutation.permute(self.state, compiler);
        }

        /// Absorbs all the items in the `input` iterator.
        #[inline]
        pub fn absorb_all<'a, A, I>(&mut self, input: I, compiler: &mut COM)
        where
            A: 'a + Absorb<P, COM>,
            I: IntoIterator<Item = &'a A>,
        {
            input
                .into_iter()
                .for_each(|item| self.absorb(item, compiler))
        }

        /// Returns the next values from `self` by squeezing reads of the values from the state.
        #[inline]
        pub fn squeeze<S>(&mut self, compiler: &mut COM) -> S
        where
            S: Squeeze<P, COM>,
        {
            let out = S::read(self.state, compiler);
            self.permutation.permute(self.state, compiler);
            out
        }

        /// Duplexes the permutation state by first modifying the state on `input`, running one
        /// permutation, and then extracting the state.
        #[inline]
        pub fn duplex<A, S>(&mut self, input: &A, compiler: &mut COM) -> S
        where
            A: Absorb<P, COM>,
            S: Squeeze<P, COM>,
        {
            input.write(self.state, compiler);
            self.permutation.permute(self.state, compiler);
            S::read(self.state, compiler)
        }

        /// Duplexes the permutation state against all the items in the `input`.
        #[inline]
        pub fn duplex_all<'a, A, I, S, C>(&mut self, input: I, compiler: &mut COM) -> C
        where
            A: 'a + Absorb<P, COM>,
            I: IntoIterator<Item = &'a A>,
            S: Squeeze<P, COM>,
            C: FromIterator<S>,
        {
            input
                .into_iter()
                .map(|item| self.duplex(item, compiler))
                .collect()
        }
    }

    /// Absorb Input Writer
    pub trait Absorb<P, COM = ()>: Sized
    where
        P: PseudorandomPermutation<COM>,
    {
        /// Writes `self` into the `state` of the [`Sponge`].
        fn write(&self, state: &mut P::Domain, compiler: &mut COM);
    }

    /// Squeeze Output Reader
    pub trait Squeeze<P, COM = ()>: Sized
    where
        P: PseudorandomPermutation<COM>,
    {
        /// Reads a value of type `Self` from the `state` of the [`Sponge`].
        fn read(state: &P::Domain, compiler: &mut COM) -> Self;
    }
}
