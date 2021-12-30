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
use core::{iter, mem};
use manta_crypto::commitment::CommitmentScheme;

/// Poseidon Permutation Specification
pub trait Specification<COM = ()> {
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
    fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Multiplies two field elements together.
    fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Adds the `rhs` field element to `self`, storing the value in `self`.
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut COM);

    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);
}

/// Internal State Vector
type State<S, COM> = Vec<<S as Specification<COM>>::Field>;

/// Returns the total number of rounds in a Poseidon permutation.
#[inline]
pub fn rounds<S, COM>() -> usize
where
    S: Specification<COM>,
{
    2 * S::FULL_ROUNDS + S::PARTIAL_ROUNDS
}

/// Poseidon Commitment
pub struct Commitment<S, COM = (), const ARITY: usize = 1>
where
    S: Specification<COM>,
{
    /// Additive Round Keys
    additive_round_keys: Vec<S::Field>,

    /// MDS Matrix
    mds_matrix: Vec<S::Field>,
}

impl<S, COM, const ARITY: usize> Commitment<S, COM, ARITY>
where
    S: Specification<COM>,
{
    /// Builds a new [`Commitment`] form `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Specification`].
    #[inline]
    pub fn new(additive_round_keys: Vec<S::Field>, mds_matrix: Vec<S::Field>) -> Self {
        assert_eq!(
            additive_round_keys.len(),
            rounds::<S, COM>() * (ARITY + 1),
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
    fn mds_matrix_multiply(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        let width = ARITY + 1;
        let mut next = Vec::with_capacity(width);
        for i in 0..width {
            #[allow(clippy::needless_collect)] // NOTE: Clippy is wrong here, we need `&mut` access.
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| S::mul(elem, &self.mds_matrix[width * i + j], compiler))
                .collect::<Vec<_>>();
            next.push(
                linear_combination
                    .into_iter()
                    .reduce(|acc, next| S::add(&acc, &next, compiler))
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
        compiler: &mut COM,
    ) -> State<S, COM> {
        let mut state = Vec::with_capacity(ARITY + 1);
        for (i, point) in iter::once(trapdoor).chain(input).enumerate() {
            let mut elem = S::add(point, &self.additive_round_keys[i], compiler);
            S::apply_sbox(&mut elem, compiler);
            state.push(elem);
        }
        self.mds_matrix_multiply(&mut state, compiler);
        state
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn full_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_assign(elem, &keys[i], compiler);
            S::apply_sbox(elem, compiler);
        }
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn partial_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_assign(elem, &keys[i], compiler);
        }
        S::apply_sbox(&mut state[0], compiler);
        self.mds_matrix_multiply(state, compiler);
    }
}

impl<S, COM, const ARITY: usize> CommitmentScheme<COM> for Commitment<S, COM, ARITY>
where
    S: Specification<COM>,
{
    type Trapdoor = S::Field;

    type Input = [S::Field; ARITY];

    type Output = S::Field;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut COM,
    ) -> Self::Output {
        let mut state = self.first_round(trapdoor, input, compiler);
        for round in 1..S::FULL_ROUNDS {
            self.full_round(round, &mut state, compiler);
        }
        for round in S::FULL_ROUNDS..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS) {
            self.partial_round(round, &mut state, compiler);
        }
        for round in (S::FULL_ROUNDS + S::PARTIAL_ROUNDS)..(2 * S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
        {
            self.full_round(round, &mut state, compiler);
        }
        state.truncate(1);
        state.remove(0)
    }
}

/// Poseidon Commitment Trapdoor Type
pub type Trapdoor<S, COM, const ARITY: usize> =
    <Commitment<S, COM, ARITY> as CommitmentScheme<COM>>::Trapdoor;

/// Poseidon Commitment Input Type
pub type Input<S, COM, const ARITY: usize> =
    <Commitment<S, COM, ARITY> as CommitmentScheme<COM>>::Input;

/// Poseidon Commitment Output Type
pub type Output<S, COM, const ARITY: usize> =
    <Commitment<S, COM, ARITY> as CommitmentScheme<COM>>::Output;

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::constraint::arkworks::{FpVar, R1CS};
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar};
    use ark_relations::ns;
    use manta_crypto::constraint::{Allocation, Constant, Variable};

    /// Compiler Type
    type Compiler<S> = R1CS<<S as Specification>::Field>;

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
        fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            *lhs + *rhs
        }

        #[inline]
        fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            *lhs * *rhs
        }

        #[inline]
        fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
            *lhs += rhs;
        }

        #[inline]
        fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
            *point = point.pow(&[Self::SBOX_EXPONENT, 0, 0, 0]);
        }
    }

    impl<S> super::Specification<Compiler<S>> for S
    where
        S: Specification,
    {
        type Field = FpVar<S::Field>;

        const FULL_ROUNDS: usize = S::FULL_ROUNDS;

        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut Compiler<S>) -> Self::Field {
            let _ = compiler;
            lhs + rhs
        }

        #[inline]
        fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut Compiler<S>) -> Self::Field {
            let _ = compiler;
            lhs * rhs
        }

        #[inline]
        fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut Compiler<S>) {
            let _ = compiler;
            *lhs += rhs;
        }

        #[inline]
        fn apply_sbox(point: &mut Self::Field, compiler: &mut Compiler<S>) {
            let _ = compiler;
            *point = point.pow_by_constant(&[Self::SBOX_EXPONENT]).expect("");
        }
    }

    impl<S, const ARITY: usize> Variable<Compiler<S>> for super::Commitment<S, Compiler<S>, ARITY>
    where
        S: Specification,
    {
        type Type = super::Commitment<S, (), ARITY>;

        type Mode = Constant;

        #[inline]
        fn new(cs: &mut Compiler<S>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
            match allocation {
                Allocation::Known(this, _) => Self {
                    additive_round_keys: this
                        .additive_round_keys
                        .iter()
                        .map(|k| FpVar::new_constant(ns!(cs.cs, ""), k))
                        .collect::<Result<Vec<_>, _>>()
                        .expect("Variable allocation is not allowed to fail."),
                    mds_matrix: this
                        .mds_matrix
                        .iter()
                        .map(|k| FpVar::new_constant(ns!(cs.cs, ""), k))
                        .collect::<Result<Vec<_>, _>>()
                        .expect("Variable allocation is not allowed to fail."),
                },
                _ => unreachable!(),
            }
        }
    }
}
