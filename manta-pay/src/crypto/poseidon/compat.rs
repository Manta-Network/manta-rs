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

//! Compatibility for Poseidon Hash Implementation

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, iter, mem};
use manta_crypto::hash::ArrayHashFunction;
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

#[cfg(any(feature = "test", test))]
use {
    core::iter::repeat,
    manta_crypto::rand::{Rand, RngCore, Sample},
};

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

    /// Returns the additive identity of the field.
    fn zero(compiler: &mut COM) -> Self::Field;

    /// Adds two field elements together.
    fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Multiplies two field elements together.
    fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Adds the `rhs` field element to `self`, storing the value in `self`.
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut COM);

    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);
}

/// Poseidon State Vector
type State<S, COM> = Vec<<S as Specification<COM>>::Field>;

/// Returns the total number of rounds in a Poseidon permutation.
#[inline]
pub fn rounds<S, COM>() -> usize
where
    S: Specification<COM>,
{
    2 * S::FULL_ROUNDS + S::PARTIAL_ROUNDS
}

/// Poseidon Hash
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "S::Field: Deserialize<'de>",
            serialize = "S::Field: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct Hasher<S, const ARITY: usize, COM = ()>
where
    S: Specification<COM>,
{
    /// Additive Round Keys
    additive_round_keys: Vec<S::Field>,

    /// MDS Matrix
    mds_matrix: Vec<S::Field>,
}

impl<S, COM, const ARITY: usize> Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
{
    /// Width of the State Buffer
    pub const WIDTH: usize = ARITY + 1;

    /// Total Number of Rounds
    pub const ROUNDS: usize = 2 * S::FULL_ROUNDS + S::PARTIAL_ROUNDS;

    /// Number of Entries in the MDS Matrix
    pub const MDS_MATRIX_SIZE: usize = Self::WIDTH * Self::WIDTH;

    /// Total Number of Additive Rounds Keys
    pub const ADDITIVE_ROUND_KEYS_COUNT: usize = Self::ROUNDS * Self::WIDTH;

    /// Builds a new [`Hasher`] from `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Specification`].
    #[inline]
    pub fn new(additive_round_keys: Vec<S::Field>, mds_matrix: Vec<S::Field>) -> Self {
        assert_eq!(
            additive_round_keys.len(),
            Self::ADDITIVE_ROUND_KEYS_COUNT,
            "Additive Rounds Keys are not the correct size."
        );
        assert_eq!(
            mds_matrix.len(),
            Self::MDS_MATRIX_SIZE,
            "MDS Matrix is not the correct size."
        );
        Self::new_unchecked(additive_round_keys, mds_matrix)
    }

    /// Builds a new [`Hasher`] from `additive_round_keys` and `mds_matrix` without
    /// checking their sizes.
    #[inline]
    fn new_unchecked(additive_round_keys: Vec<S::Field>, mds_matrix: Vec<S::Field>) -> Self {
        Self {
            additive_round_keys,
            mds_matrix,
        }
    }

    /// Returns the additive keys for the given `round`.
    #[inline]
    fn additive_keys(&self, round: usize) -> &[S::Field] {
        let width = Self::WIDTH;
        let start = round * width;
        &self.additive_round_keys[start..start + width]
    }

    /// Computes the MDS matrix multiplication against the `state`.
    #[inline]
    fn mds_matrix_multiply(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        let width = Self::WIDTH;
        let mut next = Vec::with_capacity(width);
        for i in 0..width {
            #[allow(clippy::needless_collect)]
            // NOTE: Clippy is wrong here, we need `&mut` access.
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
    fn first_round(&self, input: [&S::Field; ARITY], compiler: &mut COM) -> State<S, COM> {
        let mut state = Vec::with_capacity(Self::WIDTH);
        for (i, point) in iter::once(&S::zero(compiler)).chain(input).enumerate() {
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

impl<S, const ARITY: usize, COM> ArrayHashFunction<ARITY, COM> for Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
{
    type Input = S::Field;
    type Output = S::Field;

    #[inline]
    fn hash(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output {
        let mut state = self.first_round(input, compiler);
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

#[cfg(any(feature = "test", test))] // NOTE: This is only safe to use in a test.
impl<D, S, const ARITY: usize, COM> Sample<D> for Hasher<S, ARITY, COM>
where
    D: Clone,
    S: Specification<COM>,
    S::Field: Sample<D>,
{
    /// Samples random Poseidon parameters.
    ///
    /// # Warning
    ///
    /// This method samples the individual field elements of the parameters set, instead of
    /// producing an actually correct/safe set of additive round keys and MDS matrix.
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self {
            additive_round_keys: rng
                .sample_iter(repeat(distribution.clone()).take(Self::ADDITIVE_ROUND_KEYS_COUNT))
                .collect(),
            mds_matrix: rng
                .sample_iter(repeat(distribution).take(Self::MDS_MATRIX_SIZE))
                .collect(),
        }
    }
}

impl<S, const ARITY: usize, COM> Decode for Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
    S::Field: Decode,
{
    type Error = <S::Field as Decode>::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new_unchecked(
            (0..Self::ADDITIVE_ROUND_KEYS_COUNT)
                .map(|_| S::Field::decode(&mut reader))
                .collect::<Result<Vec<_>, _>>()?,
            (0..Self::MDS_MATRIX_SIZE)
                .map(|_| S::Field::decode(&mut reader))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

impl<S, const ARITY: usize, COM> Encode for Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
    S::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        for key in &self.additive_round_keys {
            key.encode(&mut writer)?;
        }
        for entry in &self.mds_matrix {
            entry.encode(&mut writer)?;
        }
        Ok(())
    }
}

/// Poseidon Hash Input Type
pub type Input<S, const ARITY: usize, COM = ()> =
    <Hasher<S, ARITY, COM> as ArrayHashFunction<ARITY, COM>>::Input;

/// Poseidon Commitment Output Type
pub type Output<S, const ARITY: usize, COM = ()> =
    <Hasher<S, ARITY, COM> as ArrayHashFunction<ARITY, COM>>::Output;

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::constraint::arkworks::{Fp, FpVar, R1CS};
    use manta_crypto::{
        arkworks::{
            ff::{Field, PrimeField},
            r1cs_std::fields::FieldVar,
        },
        eclair::alloc::{Allocate, Constant},
    };

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
        type Field = Fp<S::Field>;

        const FULL_ROUNDS: usize = S::FULL_ROUNDS;
        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn zero(_: &mut ()) -> Self::Field {
            Default::default()
        }

        #[inline]
        fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            Fp(lhs.0 + rhs.0)
        }

        #[inline]
        fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            Fp(lhs.0 * rhs.0)
        }

        #[inline]
        fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
            lhs.0 += rhs.0;
        }

        #[inline]
        fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
            point.0 = point.0.pow([Self::SBOX_EXPONENT, 0, 0, 0]);
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
        fn zero(compiler: &mut Compiler<S>) -> Self::Field {
            let _ = compiler;
            Self::Field::zero()
        }

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
            *point = point
                .pow_by_constant([Self::SBOX_EXPONENT])
                .expect("Exponentiation is not allowed to fail.");
        }
    }

    impl<S, const ARITY: usize> Constant<Compiler<S>> for super::Hasher<S, ARITY, Compiler<S>>
    where
        S: Specification,
    {
        type Type = super::Hasher<S, ARITY>;

        #[inline]
        fn new_constant(this: &Self::Type, compiler: &mut Compiler<S>) -> Self {
            Self {
                additive_round_keys: this
                    .additive_round_keys
                    .iter()
                    .map(|k| k.as_constant(compiler))
                    .collect(),
                mds_matrix: this
                    .mds_matrix
                    .iter()
                    .map(|k| k.as_constant(compiler))
                    .collect(),
            }
        }
    }
}
