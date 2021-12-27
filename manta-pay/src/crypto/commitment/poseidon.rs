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

//! Poseidon Commitment

use alloc::vec::Vec;
use core::{iter, marker::PhantomData, mem};
use manta_crypto::commitment::CommitmentScheme;

/// Poseidon Field
pub trait Field {
    /// Adds two field elements together.
    fn add(lhs: &Self, rhs: &Self) -> Self;

    /// Multiplies two field elements together.
    fn mul(lhs: &Self, rhs: &Self) -> Self;

    /// Adds the `rhs` field element to `self`, storing the value in `self`.
    fn add_assign(&mut self, rhs: &Self);
}

/// Poseidon Configuration
pub trait Configuration {
    /// Number of Full Rounds
    ///
    /// This is counted twice for the first set of full rounds and then the second set after the
    /// partial rounds.
    const FULL_ROUNDS: usize;

    /// Number of Partial Rounds
    const PARTIAL_ROUNDS: usize;

    /// Field Type
    type Field: Field;

    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field);
}

/// Internal State Vector
type State<C> = Vec<<C as Configuration>::Field>;

/// Returns the total number of rounds in a Poseidon permutation.
#[inline]
pub fn rounds<C>() -> usize
where
    C: Configuration,
{
    2 * C::FULL_ROUNDS + C::PARTIAL_ROUNDS
}

/// Poseidon Permutation Parameters
pub struct Parameters<C, const ARITY: usize>
where
    C: Configuration,
{
    /// Additive Round Keys
    additive_round_keys: Vec<C::Field>,

    /// MDS Matrix
    mds_matrix: Vec<C::Field>,
}

impl<C, const ARITY: usize> Parameters<C, ARITY>
where
    C: Configuration,
{
    /// Builds a new [`Parameters`] form `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Configuration`].
    #[inline]
    pub fn new(additive_round_keys: Vec<C::Field>, mds_matrix: Vec<C::Field>) -> Self {
        assert_eq!(
            additive_round_keys.len(),
            rounds::<C>() * (ARITY + 1),
            "Additive Rounds Keys are not the correct size."
        );
        assert_eq!(
            mds_matrix.len(),
            (ARITY + 1).pow(2),
            "MDS Matrix is not the correct size."
        );
        Self {
            additive_round_keys,
            mds_matrix,
        }
    }

    /// Returns the additive keys for the given `round`.
    #[inline]
    fn additive_keys(&self, round: usize) -> &[C::Field] {
        let width = ARITY + 1;
        let start = round * width;
        &self.additive_round_keys[start..start + width]
    }

    /// Computes the MDS matrix multiplication against the `state`.
    #[inline]
    fn mds_matrix_multiply(&self, state: &mut State<C>) {
        let width = ARITY + 1;
        let mut next = Vec::with_capacity(width);
        for i in 0..width {
            next.push(
                state
                    .iter()
                    .enumerate()
                    .map(|(j, elem)| C::Field::mul(elem, &self.mds_matrix[width * i + j]))
                    .reduce(|acc, next| C::Field::add(&acc, &next))
                    .unwrap(),
            );
        }
        mem::swap(&mut next, state);
    }

    /// Computes the first round of the Poseidon permutation from `trapdoor` and `input`.
    #[inline]
    fn first_round(&self, trapdoor: &C::Field, input: &[C::Field; ARITY]) -> State<C> {
        let mut state = Vec::with_capacity(ARITY + 1);
        for (i, point) in iter::once(trapdoor).chain(input).enumerate() {
            let mut elem = C::Field::add(point, &self.additive_round_keys[i]);
            C::apply_sbox(&mut elem);
            state.push(elem);
        }
        self.mds_matrix_multiply(&mut state);
        state
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn full_round(&self, round: usize, state: &mut State<C>) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            C::Field::add_assign(elem, &keys[i]);
            C::apply_sbox(elem);
        }
        self.mds_matrix_multiply(state);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn partial_round(&self, round: usize, state: &mut State<C>) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            C::Field::add_assign(elem, &keys[i]);
        }
        C::apply_sbox(&mut state[0]);
        self.mds_matrix_multiply(state);
    }
}

/// Poseidon Commitment Scheme
pub struct Commitment<C, const ARITY: usize>(PhantomData<C>)
where
    C: Configuration;

impl<C, const ARITY: usize> CommitmentScheme for Commitment<C, ARITY>
where
    C: Configuration,
{
    type Parameters = Parameters<C, ARITY>;

    type Trapdoor = C::Field;

    type Input = [C::Field; ARITY];

    type Output = C::Field;

    #[inline]
    fn commit(
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        let mut state = parameters.first_round(trapdoor, input);
        for round in 1..C::FULL_ROUNDS {
            parameters.full_round(round, &mut state);
        }
        for round in C::FULL_ROUNDS..(C::FULL_ROUNDS + C::PARTIAL_ROUNDS) {
            parameters.partial_round(round, &mut state);
        }
        for round in (C::FULL_ROUNDS + C::PARTIAL_ROUNDS)..(2 * C::FULL_ROUNDS + C::PARTIAL_ROUNDS)
        {
            parameters.full_round(round, &mut state);
        }
        state.truncate(1);
        state.remove(0)
    }
}

/// Constraint System Gadgets
pub mod constraint {}

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {}
