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

// TODO: Describe the contract for `Specification`.

use alloc::vec::Vec;
use core::{iter, marker::PhantomData, mem};
use manta_crypto::commitment::CommitmentScheme;

/// Poseidon Permutation Specification
pub trait Specification<J = ()> {
    /// Field Type
    type Field;

    /// Number of Full Rounds
    ///
    /// This is counted twice for the first set of full rounds and then the second set after the
    /// partial rounds.
    const FULL_ROUNDS: usize;

    /// Number of Partial Rounds
    const PARTIAL_ROUNDS: usize;

    /// Adds two field elements together.
    fn add(compiler: &mut J, lhs: &Self::Field, rhs: &Self::Field) -> Self::Field;

    /// Multiplies two field elements together.
    fn mul(compiler: &mut J, lhs: &Self::Field, rhs: &Self::Field) -> Self::Field;

    /// Adds the `rhs` field element to `self`, storing the value in `self`.
    fn add_assign(compiler: &mut J, lhs: &mut Self::Field, rhs: &Self::Field);

    /// Applies the S-BOX to `point`.
    fn apply_sbox(compiler: &mut J, point: &mut Self::Field);
}

/// Internal State Vector
type State<S, J> = Vec<<S as Specification<J>>::Field>;

/// Returns the total number of rounds in a Poseidon permutation.
#[inline]
pub fn rounds<S, J>() -> usize
where
    S: Specification<J>,
{
    2 * S::FULL_ROUNDS + S::PARTIAL_ROUNDS
}

/// Poseidon Permutation Parameters
pub struct Parameters<S, J = (), const ARITY: usize = 1>
where
    S: Specification<J>,
{
    /// Additive Round Keys
    additive_round_keys: Vec<S::Field>,

    /// MDS Matrix
    mds_matrix: Vec<S::Field>,
}

impl<S, J, const ARITY: usize> Parameters<S, J, ARITY>
where
    S: Specification<J>,
{
    /// Builds a new [`Parameters`] form `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Specification`].
    #[inline]
    pub fn new(additive_round_keys: Vec<S::Field>, mds_matrix: Vec<S::Field>) -> Self {
        assert_eq!(
            additive_round_keys.len(),
            rounds::<S, J>() * (ARITY + 1),
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
    fn additive_keys(&self, round: usize) -> &[S::Field] {
        let width = ARITY + 1;
        let start = round * width;
        &self.additive_round_keys[start..start + width]
    }

    /// Computes the MDS matrix multiplication against the `state`.
    #[inline]
    fn mds_matrix_multiply(&self, state: &mut State<S, J>, compiler: &mut J) {
        let width = ARITY + 1;
        let mut next = Vec::with_capacity(width);
        for i in 0..width {
            #[allow(clippy::needless_collect)] // NOTE: Clippy is wrong here, we need `&mut` access.
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| S::mul(compiler, elem, &self.mds_matrix[width * i + j]))
                .collect::<Vec<_>>();
            next.push(
                linear_combination
                    .into_iter()
                    .reduce(|acc, next| S::add(compiler, &acc, &next))
                    .unwrap(),
            );
        }
        mem::swap(&mut next, state);
    }

    /// Computes the first round of the Poseidon permutation from `trapdoor` and `input`.
    #[inline]
    fn first_round(
        &self,
        trapdoor: &S::Field,
        input: &[S::Field; ARITY],
        compiler: &mut J,
    ) -> State<S, J> {
        let mut state = Vec::with_capacity(ARITY + 1);
        for (i, point) in iter::once(trapdoor).chain(input).enumerate() {
            let mut elem = S::add(compiler, point, &self.additive_round_keys[i]);
            S::apply_sbox(compiler, &mut elem);
            state.push(elem);
        }
        self.mds_matrix_multiply(&mut state, compiler);
        state
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn full_round(&self, round: usize, state: &mut State<S, J>, compiler: &mut J) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_assign(compiler, elem, &keys[i]);
            S::apply_sbox(compiler, elem);
        }
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn partial_round(&self, round: usize, state: &mut State<S, J>, compiler: &mut J) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_assign(compiler, elem, &keys[i]);
        }
        S::apply_sbox(compiler, &mut state[0]);
        self.mds_matrix_multiply(state, compiler);
    }
}

/// Poseidon Commitment Scheme
pub struct Commitment<S, J = (), const ARITY: usize = 1>(PhantomData<(S, J)>)
where
    S: Specification<J>;

impl<S, J, const ARITY: usize> CommitmentScheme<J> for Commitment<S, J, ARITY>
where
    S: Specification<J>,
{
    type Parameters = Parameters<S, J, ARITY>;

    type Trapdoor = S::Field;

    type Input = [S::Field; ARITY];

    type Output = S::Field;

    #[inline]
    fn commit(
        compiler: &mut J,
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        let mut state = parameters.first_round(trapdoor, input, compiler);
        for round in 1..S::FULL_ROUNDS {
            parameters.full_round(round, &mut state, compiler);
        }
        for round in S::FULL_ROUNDS..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS) {
            parameters.partial_round(round, &mut state, compiler);
        }
        for round in (S::FULL_ROUNDS + S::PARTIAL_ROUNDS)..(2 * S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
        {
            parameters.full_round(round, &mut state, compiler);
        }
        state.truncate(1);
        state.remove(0)
    }
}

/// Poseidon Commitment Trapdoor Type
pub type Trapdoor<S, J, const ARITY: usize> =
    <Commitment<S, J, ARITY> as CommitmentScheme<J>>::Trapdoor;

/// Poseidon Commitment Input Type
pub type Input<S, J, const ARITY: usize> = <Commitment<S, J, ARITY> as CommitmentScheme<J>>::Input;

/// Poseidon Commitment Output Type
pub type Output<S, J, const ARITY: usize> =
    <Commitment<S, J, ARITY> as CommitmentScheme<J>>::Output;

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::constraint::arkworks::{FpVar, R1CS};
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::fields::FieldVar;

    /// Poseidon Permutation Specification
    pub trait Specification {
        /// Field Type
        type Field: PrimeField;

        /// Number of Full Rounds
        ///
        /// This is counted twice for the first set of full rounds and then the second set after the
        /// partial rounds.
        const FULL_ROUNDS: usize;

        /// Number of Partial Rounds
        const PARTIAL_ROUNDS: usize;

        /// S-BOX Exponenet
        const SBOX_EXPONENT: u64;
    }

    impl<S> super::Specification for S
    where
        S: Specification,
    {
        type Field = S::Field;

        const FULL_ROUNDS: usize = S::FULL_ROUNDS;

        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn add(_: &mut (), lhs: &Self::Field, rhs: &Self::Field) -> Self::Field {
            *lhs + *rhs
        }

        #[inline]
        fn mul(_: &mut (), lhs: &Self::Field, rhs: &Self::Field) -> Self::Field {
            *lhs * *rhs
        }

        #[inline]
        fn add_assign(_: &mut (), lhs: &mut Self::Field, rhs: &Self::Field) {
            *lhs += rhs;
        }

        #[inline]
        fn apply_sbox(_: &mut (), point: &mut Self::Field) {
            *point = point.pow(&[Self::SBOX_EXPONENT, 0, 0, 0]);
        }
    }

    impl<S> super::Specification<R1CS<S::Field>> for S
    where
        S: Specification,
    {
        type Field = FpVar<S::Field>;

        const FULL_ROUNDS: usize = S::FULL_ROUNDS;

        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn add(compiler: &mut R1CS<S::Field>, lhs: &Self::Field, rhs: &Self::Field) -> Self::Field {
            let _ = compiler;
            lhs + rhs
        }

        #[inline]
        fn mul(compiler: &mut R1CS<S::Field>, lhs: &Self::Field, rhs: &Self::Field) -> Self::Field {
            let _ = compiler;
            lhs * rhs
        }

        #[inline]
        fn add_assign(compiler: &mut R1CS<S::Field>, lhs: &mut Self::Field, rhs: &Self::Field) {
            let _ = compiler;
            *lhs += rhs;
        }

        #[inline]
        fn apply_sbox(compiler: &mut R1CS<S::Field>, point: &mut Self::Field) {
            let _ = compiler;
            *point = point.pow_by_constant(&[Self::SBOX_EXPONENT]).expect("");
        }
    }
}
