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

use crate::constraint::Native;

/// Pseudorandom Permutation
pub trait PseudorandomPermutation<COM = ()> {
    /// Permutation Domain Type
    ///
    /// A pseudorandom permutation acts on this domain, and should be a bijection on this space.
    type Domain;

    /// Computes the permutation of `state` inside of `compiler`.
    fn permute_with(&self, state: &mut Self::Domain, compiler: &mut COM);

    /// Computes the permutation of `state`.
    #[inline]
    fn permute(&self, state: &mut Self::Domain)
    where
        COM: Native,
    {
        self.permute_with(state, &mut COM::compiler())
    }
}

impl<P, COM> PseudorandomPermutation<COM> for &P
where
    P: PseudorandomPermutation<COM>,
{
    type Domain = P::Domain;

    #[inline]
    fn permute_with(&self, state: &mut Self::Domain, compiler: &mut COM) {
        (*self).permute_with(state, compiler)
    }

    #[inline]
    fn permute(&self, state: &mut Self::Domain)
    where
        COM: Native,
    {
        (*self).permute(state)
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

    /// Returns the pseudorandom permutation associated to the given `key` inside the `compiler`.
    fn permutation_with(&self, key: &Self::Key, compiler: &mut COM) -> Self::Permutation;

    /// Returns the pseudorandom permutation associated to the given `key`.
    #[inline]
    fn permutation(&self, key: &Self::Key) -> Self::Permutation
    where
        COM: Native,
    {
        self.permutation_with(key, &mut COM::compiler())
    }

    /// Computes the permutation of `state` under the pseudorandom permutation derived from `key`
    /// inside of `compiler`.
    #[inline]
    fn permute_with(&self, key: &Self::Key, state: &mut Self::Domain, compiler: &mut COM) {
        self.permutation_with(key, compiler)
            .permute_with(state, compiler)
    }

    /// Computes the permutation of `state` under the pseudorandom permutation derived from `key`.
    #[inline]
    fn permute(&self, key: &Self::Key, state: &mut Self::Domain)
    where
        COM: Native,
    {
        self.permutation(key).permute(state)
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
    fn permutation_with(&self, key: &Self::Key, compiler: &mut COM) -> Self::Permutation {
        (*self).permutation_with(key, compiler)
    }

    #[inline]
    fn permutation(&self, key: &Self::Key) -> Self::Permutation
    where
        COM: Native,
    {
        (*self).permutation(key)
    }

    #[inline]
    fn permute_with(&self, key: &Self::Key, state: &mut Self::Domain, compiler: &mut COM) {
        (*self).permute_with(key, state, compiler)
    }

    #[inline]
    fn permute(&self, key: &Self::Key, state: &mut Self::Domain)
    where
        COM: Native,
    {
        (*self).permute(key, state)
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

        /// Updates `self` by absorbing writes into the state with `input` inside the
        /// `compiler`.
        #[inline]
        pub fn absorb_with<A>(&mut self, input: &A, compiler: &mut COM)
        where
            A: Absorb<P, COM>,
        {
            input.write_with(self.state, compiler);
            self.permutation.permute_with(self.state, compiler);
        }

        /// Absorbs all the items in the `input` iterator inside the `compiler`.
        #[inline]
        pub fn absorb_all_with<'a, A, I>(&mut self, input: I, compiler: &mut COM)
        where
            A: 'a + Absorb<P, COM>,
            I: IntoIterator<Item = &'a A>,
        {
            input
                .into_iter()
                .for_each(|item| self.absorb_with(item, compiler))
        }

        /// Returns the next values from `self` by squeezing reads of the values from the state
        /// inside of `compiler`.
        #[inline]
        pub fn squeeze_with<S>(&mut self, compiler: &mut COM) -> S
        where
            S: Squeeze<P, COM>,
        {
            let out = S::read_with(self.state, compiler);
            self.permutation.permute_with(self.state, compiler);
            out
        }

        /// Duplexes the permutation state by first modifying the state on `input`, running one
        /// permutation, and then extracting the state inside of `compiler`.
        #[inline]
        pub fn duplex_with<A, S>(&mut self, input: &A, compiler: &mut COM) -> S
        where
            A: Absorb<P, COM>,
            S: Squeeze<P, COM>,
        {
            input.write_with(self.state, compiler);
            self.permutation.permute_with(self.state, compiler);
            S::read_with(self.state, compiler)
        }

        /// Duplexes the permutation state against all the items in the `input` inside of
        /// `compiler`.
        #[inline]
        pub fn duplex_all_with<'a, A, I, S, C>(&mut self, input: I, compiler: &mut COM) -> C
        where
            A: 'a + Absorb<P, COM>,
            I: IntoIterator<Item = &'a A>,
            S: Squeeze<P, COM>,
            C: FromIterator<S>,
        {
            input
                .into_iter()
                .map(|item| self.duplex_with(item, compiler))
                .collect()
        }
    }

    impl<'p, P> Sponge<'p, P>
    where
        P: PseudorandomPermutation,
    {
        /// Updates `self` by absorbing writes into the state with `input`.
        #[inline]
        pub fn absorb<A>(&mut self, input: &A)
        where
            A: Absorb<P>,
        {
            input.write(self.state);
            self.permutation.permute(self.state);
        }

        /// Absorbs all the items in the `input` iterator.
        #[inline]
        pub fn absorb_all<'a, A, I>(&mut self, input: I)
        where
            A: 'a + Absorb<P>,
            I: IntoIterator<Item = &'a A>,
        {
            input.into_iter().for_each(|item| self.absorb(item))
        }

        /// Returns the next values from `self` by squeezing reads of the values from the state with
        /// `output`.
        #[inline]
        pub fn squeeze<S>(&mut self) -> S
        where
            S: Squeeze<P>,
        {
            let out = S::read(self.state);
            self.permutation.permute(self.state);
            out
        }

        /// Duplexes the permutation state by first modifying the state with `input`, running one
        /// permutation, and then extracting the state with `output`.
        #[inline]
        pub fn duplex<A, S>(&mut self, input: &A) -> S
        where
            A: Absorb<P>,
            S: Squeeze<P>,
        {
            input.write(self.state);
            self.permutation.permute(self.state);
            S::read(self.state)
        }

        /// Duplexes the permutation state against all the items in the `input`.
        #[inline]
        pub fn duplex_all<'a, A, I, S, C>(&mut self, input: I) -> C
        where
            A: 'a + Absorb<P>,
            I: IntoIterator<Item = &'a A>,
            S: Squeeze<P>,
            C: FromIterator<S>,
        {
            input.into_iter().map(|item| self.duplex(item)).collect()
        }
    }

    /// Absorb Input Writer
    pub trait Absorb<P, COM = ()>: Sized
    where
        P: PseudorandomPermutation<COM>,
    {
        /// Writes `self` into the `state` of the [`Sponge`] inside of `compiler`.
        fn write_with(&self, state: &mut P::Domain, compiler: &mut COM);

        /// Writes `self` into the `state` of the [`Sponge`].
        #[inline]
        fn write(&self, state: &mut P::Domain)
        where
            COM: Native,
        {
            self.write_with(state, &mut COM::compiler())
        }
    }

    /// Squeeze Output Reader
    pub trait Squeeze<P, COM = ()>: Sized
    where
        P: PseudorandomPermutation<COM>,
    {
        /// Reads a value of type `Self` from the `state` of the [`Sponge`] inside of `compiler`.
        fn read_with(state: &P::Domain, compiler: &mut COM) -> Self;

        /// Reads a value of type `Self` from the `state` of the [`Sponge`].
        #[inline]
        fn read(state: &P::Domain) -> Self
        where
            COM: Native,
        {
            Self::read_with(state, &mut COM::compiler())
        }
    }
}
