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

//! Sponges over Pseudorandom Permutations

use crate::permutation::PseudorandomPermutation;

/// Absorb Input Writer
///
/// This `trait` is used to input a single element of data into the state of the sponge. For
/// multiple elements, the sponge needs to run [`absorb_all`](Sponge::absorb_all) to run the
/// permutation between elements.
pub trait Absorb<P, COM = ()>: Sized
where
    P: PseudorandomPermutation<COM>,
{
    /// Writes `self` into the `state` of the [`Sponge`].
    fn write(&self, state: &mut P::Domain, compiler: &mut COM);
}

/// Squeeze Output Reader
///
/// This `trait` is used to output a single element of data from the state of the sponge. For
/// multiple elements, the sponge needs to run [`squeeze`](Sponge::squeeze) multiple times to run
/// the permutation between elements.
pub trait Squeeze<P, COM = ()>: Sized
where
    P: PseudorandomPermutation<COM>,
{
    /// Reads a value of type `Self` from the `state` of the [`Sponge`].
    fn read(state: &P::Domain, compiler: &mut COM) -> Self;
}

/// Permutation Sponge
///
/// This `struct` is a general sponge-like construction which takes a permutation and repeatedly
/// applies it to an internal state, with read and write access to the state via the [`absorb`]
/// and [`squeeze`] methods. Using a concrete permutation and fixed [`absorb`] input and [`squeeze`]
/// output functions one can build the classical sponge constructions.
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
