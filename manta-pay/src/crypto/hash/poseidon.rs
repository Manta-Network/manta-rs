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

//! Poseidon Hash Function

// TODO: Describe the contract for `Specification`.
// TODO: Add more methods to the `Specification` trait for optimization.

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, iter, mem};
use manta_crypto::hash::ArrayHashFunction;
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

use super::poseidon_parameter_generation::{round_constants::generate_round_constants, mds::MdsMatrices};

#[cfg(any(feature = "test", test))]
use manta_crypto::rand::{CryptoRng, RngCore, Sample};

/// Poseidon Permutation Specification
pub trait Specification<COM = ()> {
    /// Field used as state
    type Field;

    /// Field used as constants
    type ParameterField;

    /// Number of bits of modulus of the field.
    const MODULUS_BITS: usize;

    /// Number of Full Rounds
    ///
    /// This is counted twice for the first set of full rounds and then the second set after the
    /// partial rounds.
    const FULL_ROUNDS: usize;

    /// Number of Partial Rounds
    const PARTIAL_ROUNDS: usize;

    /// Returns the domain tag. TODO: May update domain_tag for different applications
    fn domain_tag(compiler: &mut COM, arity: usize) -> Self::Field;

    /// Adds two field elements together.
    fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Add a field element with a constant
    fn addi(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Multiplies two field elements together.
    fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Multiplies a field element with a constant
    fn muli(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Adds the `rhs` field element to `lhs` field element, storing the value in `lhs`
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut COM);

    /// Adds the `rhs` constant to `lhs` field element, storing the value in `lhs`
    fn addi_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, compiler: &mut COM);

    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);

    /// Returns the additive identity of the parameter field
    fn param_zero() -> Self::ParameterField;

    /// Returns the multiplicative identity of the parameter field
    fn param_one() -> Self::ParameterField;

    /// Add two parameter field elements together
    fn param_add(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField;

    /// Add the `rhs` parameter field element to `lhs` parameter field element, storing the value in `lhs`
    fn param_add_assign(lhs: &mut Self::ParameterField, rhs: &Self::ParameterField);

    /// Multiply two parameter field elements together
    fn param_mul(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField;

    /// returns (lhs - rhs)
    fn param_sub(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField;

    /// returns (lhs == rhs)
    fn param_eq(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> bool;

    /// Computes the multiplicative inverse of a parameter field elements
    fn inverse(elem: &Self::ParameterField) -> Option<Self::ParameterField>;

    /// Convert from bits into a parameter field element in little endian order. Return None if bits is out of range.
    fn try_from_bits_le(bits: &[bool]) -> Option<Self::ParameterField>;

    /// Convert from bytes into a parameter field element in little endian order. If the number of bytes is out of range, the result will be modulo.   
    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self::ParameterField;

    /// Convert a u64 value to a parameter field element
    fn from_u64_to_param(elem: u64) -> Self::ParameterField;
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
            deserialize = "S::ParameterField: Deserialize<'de>",
            serialize = "S::ParameterField: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::ParameterField: Clone"),
    Debug(bound = "S::ParameterField: Debug"),
    Eq(bound = "S::ParameterField: Eq"),
    Hash(bound = "S::ParameterField: Hash"),
    PartialEq(bound = "S::ParameterField: PartialEq")
)]
pub struct Hasher<S, COM, const ARITY: usize>
where
    S: Specification<COM>,
{
    /// Additive Round Keys
    additive_round_keys: Vec<S::ParameterField>,

    /// MDS Matrix
    mds_matrix: Vec<S::ParameterField>,
}

impl<S, COM, const ARITY: usize> Hasher<S, COM, ARITY>
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
    pub fn new(additive_round_keys: Vec<S::ParameterField>, mds_matrix: Vec<S::ParameterField>) -> Self {
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
    fn new_unchecked(additive_round_keys: Vec<S::ParameterField>, mds_matrix: Vec<S::ParameterField>) -> Self {
        Self {
            additive_round_keys,
            mds_matrix,
        }
    }

    /// Returns the additive keys for the given `round`.
    #[inline]
    fn additive_keys(&self, round: usize) -> &[S::ParameterField] {
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
            #[allow(clippy::needless_collect)] // NOTE: Clippy is wrong here, we need `&mut` access.
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| S::muli(elem, &self.mds_matrix[width * i + j], compiler))
                .collect::<Vec<_>>(); // TODO: Check whether mds_matrix here is correct, in terms of row-major and col-major
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
        for (i, point) in iter::once(&S::domain_tag(compiler, ARITY)).chain(input).enumerate() {
            let mut elem = S::addi(point, &self.additive_round_keys[i], compiler);
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
            S::addi_assign(elem, &keys[i], compiler);
            S::apply_sbox(elem, compiler);
        }
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn partial_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::addi_assign(elem, &keys[i], compiler);
        }
        S::apply_sbox(&mut state[0], compiler);
        self.mds_matrix_multiply(state, compiler);
    }
}

impl<S, COM, const ARITY: usize> ArrayHashFunction<COM, ARITY> for Hasher<S, COM, ARITY>
where
    S: Specification<COM>,
{
    type Input = S::Field;
    type Output = S::Field;

    #[inline]
    fn hash_in(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output {
        let mut state = self.first_round(input, compiler);
        let half_full_round = S::FULL_ROUNDS/2;
        for round in 1..half_full_round {
            self.full_round(round, &mut state, compiler);
        }
        for round in half_full_round..(half_full_round + S::PARTIAL_ROUNDS) {
            self.partial_round(round, &mut state, compiler);
        }
        for round in (half_full_round + S::PARTIAL_ROUNDS)..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
        {
            self.full_round(round, &mut state, compiler);
        }
        state.truncate(1);
        state.remove(0)
    }
}

// #[cfg(any(feature = "test", test))] // NOTE: This is only safe to use in a test.
impl<D, S, COM, const ARITY: usize> Sample<D> for Hasher<S, COM, ARITY>
where
    D: Clone,
    S: Specification<COM> + Clone,
    <S as Specification<COM>>::ParameterField: Sample<D> + Debug + Copy + Eq,
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
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        let _ = rng;
        let (round_constants, _) = generate_round_constants::<S, COM>(
            S::MODULUS_BITS as u64, 
            Self::WIDTH,
            <S as Specification<COM>>::FULL_ROUNDS, 
            <S as Specification<COM>>::PARTIAL_ROUNDS,
        );

        let mds_matrices = MdsMatrices::<S, COM>::generate_mds(Self::WIDTH);

        Self {
            additive_round_keys: round_constants,
            mds_matrix: mds_matrices.to_row_major(),
        }
        // Self {
        //     additive_round_keys: rng
        //         .sample_iter(repeat(distribution.clone()).take(Self::ADDITIVE_ROUND_KEYS_COUNT))
        //         .collect(),
        //     mds_matrix: rng
        //         .sample_iter(repeat(distribution).take(Self::MDS_MATRIX_SIZE))
        //         .collect(),
        // }
    }
}

impl<S, COM, const ARITY: usize> Decode for Hasher<S, COM, ARITY>
where
    S: Specification<COM>,
    S::ParameterField: Decode,
{
    type Error = <S::ParameterField as Decode>::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new_unchecked(
            (0..Self::ADDITIVE_ROUND_KEYS_COUNT)
                .map(|_| S::ParameterField::decode(&mut reader))
                .collect::<Result<Vec<_>, _>>()?,
            (0..Self::MDS_MATRIX_SIZE)
                .map(|_| S::ParameterField::decode(&mut reader))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

impl<S, COM, const ARITY: usize> Encode for Hasher<S, COM, ARITY>
where
    S: Specification<COM>,
    S::ParameterField: Encode,
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
pub type Input<S, COM, const ARITY: usize> =
    <Hasher<S, COM, ARITY> as ArrayHashFunction<COM, ARITY>>::Input;

/// Poseidon Commitment Output Type
pub type Output<S, COM, const ARITY: usize> =
    <Hasher<S, COM, ARITY> as ArrayHashFunction<COM, ARITY>>::Output;

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::constraint::arkworks::{Fp, FpVar, R1CS};
    use ark_std::{One, Zero};
    use ark_ff::{BigInteger, Field, PrimeField, FpParameters};
    use ark_r1cs_std::{fields::FieldVar, alloc::AllocVar};
    use manta_crypto::constraint::Constant;

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
        type ParameterField = Fp<S::Field>;

        const MODULUS_BITS: usize = <S::Field as PrimeField>::Params::MODULUS_BITS as usize;

        const FULL_ROUNDS: usize = S::FULL_ROUNDS;

        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn domain_tag(_: &mut (), arity: usize) -> Self::Field {
            Fp(S::Field::from(((1 << arity)-1) as u64))
        }

        #[inline]
        fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            Fp(lhs.0 + rhs.0)
        }

        // When COM = (), we do not distinguish Field and ParameterField. So addi() has the same computation as add()
        #[inline]
        fn addi(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
            Fp(lhs.0 + rhs.0)
        }

        #[inline]
        fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            Fp(lhs.0 * rhs.0)
        }

        // When COM = (), we do not distinguish Field and ParameterField. So muli() has the same computation as mul()
        #[inline]
        fn muli(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
            Fp(lhs.0 * rhs.0)
        }

        #[inline]
        fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
            lhs.0 += rhs.0;
        }

        // When COM = (), we do not distinguish Field and ParameterField. So addi_assign() has the same computation as add_assign()
        #[inline]
        fn addi_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut ()) {
            lhs.0 += rhs.0;
        }

        #[inline]
        fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
            point.0 = point.0.pow(&[Self::SBOX_EXPONENT, 0, 0, 0]);
        }

        #[inline]
        fn param_zero() -> Self::ParameterField {
            Fp(<S::Field as Zero>::zero())
        }

        #[inline]
        fn param_one() -> Self::ParameterField  {
            Fp(<S::Field as One>::one())
        }

        #[inline]
        fn param_add(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField  {
            Fp(lhs.0 + rhs.0)
        }

        #[inline]
        fn param_add_assign(lhs: &mut Self::ParameterField, rhs: &Self::ParameterField) {
            lhs.0 = lhs.0 + rhs.0;
        }

        #[inline]
        fn param_sub(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField {
            Fp(lhs.0 - rhs.0)
        }

        #[inline]
        fn param_mul(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField  {
            Fp(lhs.0 * rhs.0)
        }

        #[inline]
        fn param_eq(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> bool {
            lhs.0 == rhs.0
        }

        #[inline]
        fn inverse(elem: &Self::ParameterField) -> Option<Self::ParameterField>  {
            let m_inverse = S::Field::inverse(&elem.0);
            if let Some(m_inverse) = m_inverse {
                return Some(Fp(m_inverse));
            } else {
                return None;
            }
        }

        #[inline]
        fn try_from_bits_le(bits: &[bool]) -> Option<Self::ParameterField>  {
            let bigint = <S::Field as PrimeField>::BigInt::from_bits_le(&bits);
            let value = S::Field::from_repr(bigint);
            if let Some(value) = value {
                return Some(Fp(value));
            } else {
                return None;
            }
        }

        #[inline]
        fn from_le_bytes_mod_order(bytes: &[u8]) -> Self::ParameterField {
            Fp(S::Field::from_le_bytes_mod_order(bytes))
        }

        #[inline]
        fn from_u64_to_param(elem: u64) -> Self::ParameterField {
            Fp(S::Field::from(elem))
        }
    }

    impl<S> super::Specification<Compiler<S>> for S
    where
        S: Specification,
    {
        type Field = FpVar<S::Field>;
        type ParameterField = Fp<S::Field>;

        const MODULUS_BITS: usize = <S::Field as PrimeField>::Params::MODULUS_BITS as usize;

        const FULL_ROUNDS: usize = S::FULL_ROUNDS;
        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn domain_tag(compiler: &mut Compiler<S>, arity: usize) -> Self::Field {
            let v = S::Field::from(((1 << arity)-1) as u64);
            FpVar::new_witness(compiler.cs.clone(), || Ok(v)).unwrap()
        }

        #[inline]
        fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
            lhs + rhs
        }

        #[inline]
        fn addi(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut Compiler<S>) -> Self::Field {
            lhs + FpVar::Constant(rhs.0)
        }

        #[inline]
        fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
            lhs * rhs
        }

        #[inline]
        fn muli(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut Compiler<S>) -> Self::Field {
            lhs * FpVar::Constant(rhs.0)
        }

        #[inline]
        fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) {
            *lhs += rhs;
        }

        #[inline]
        fn addi_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut Compiler<S>) {
            *lhs += FpVar::Constant(rhs.0)
        }
        
        #[inline]
        fn apply_sbox(point: &mut Self::Field, _: &mut Compiler<S>) {
            *point = point
                .pow_by_constant(&[Self::SBOX_EXPONENT])
                .expect("Exponentiation is not allowed to fail.");
        }

        #[inline]
        fn param_zero() -> Self::ParameterField {
            Fp(<S::Field as Zero>::zero())
        }

        #[inline]
        fn param_one() -> Self::ParameterField  {
            Fp(<S::Field as One>::one())
        }

        #[inline]
        fn param_add(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField  {
            Fp(lhs.0 + rhs.0)
        }

        #[inline]
        fn param_add_assign(lhs: &mut Self::ParameterField, rhs: &Self::ParameterField) {
            lhs.0 = lhs.0 + rhs.0;
        }

        #[inline]
        fn param_sub(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField {
            Fp(lhs.0 - rhs.0)
        }
    
        #[inline]
        fn param_mul(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> Self::ParameterField  {
            Fp(lhs.0 * rhs.0)
        }

        #[inline]
        fn param_eq(lhs: &Self::ParameterField, rhs: &Self::ParameterField) -> bool {
            lhs.0 == rhs.0
        }

        #[inline]
        fn inverse(elem: &Self::ParameterField) -> Option<Self::ParameterField>  {
            let m_inverse = S::Field::inverse(&elem.0);
            if let Some(m_inverse) = m_inverse {
                return Some(Fp(m_inverse));
            } else {
                return None;
            }
        }

        #[inline]
        fn try_from_bits_le(bits: &[bool]) -> Option<Self::ParameterField>  {
            let bigint = <S::Field as PrimeField>::BigInt::from_bits_le(&bits);
            let value = S::Field::from_repr(bigint);
            if let Some(value) = value {
                return Some(Fp(value));
            } else {
                return None;
            }
        }

        #[inline]
        fn from_le_bytes_mod_order(bytes: &[u8]) -> Self::ParameterField {
            Fp(S::Field::from_le_bytes_mod_order(bytes))
        }

        #[inline]
        fn from_u64_to_param(elem: u64) -> Self::ParameterField {
            Fp(S::Field::from(elem))
        }
    }

    impl<S, const ARITY: usize> Constant<Compiler<S>> for super::Hasher<S, Compiler<S>, ARITY>
    where
        S: Specification,
    {
        type Type = super::Hasher<S, (), ARITY>;

        #[inline]
        fn new_constant(this: &Self::Type, compiler: &mut Compiler<S>) -> Self {
            let _ = compiler;
            Self {
                additive_round_keys: this.additive_round_keys.clone(),
                mds_matrix: this.mds_matrix.clone()
            }
        }
    }
}
