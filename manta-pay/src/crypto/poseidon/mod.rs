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

//! Poseidon Permutation Implementation

use crate::crypto::poseidon::{
    matrix::MatrixOperations, mds::MdsMatrices, round_constants::generate_round_constants,
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash, iter, mem, slice};
use manta_crypto::{
    hash::ArrayHashFunction,
    permutation::PseudorandomPermutation,
    rand::{Rand, RngCore, Sample},
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    vec::VecExt,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod compat;
pub mod constants;
pub mod lfsr;
pub mod matrix;
pub mod mds;
pub mod preprocessing;
pub mod round_constants;

/// Field Element
pub trait Field {
    /// Returns the additive identity of the field.
    fn zero() -> Self;

    /// Checks if the field element equals the result of calling [`zero`](Self::zero).
    fn is_zero(&self) -> bool;

    /// Returns the multiplicative identity of the field.
    fn one() -> Self;

    /// Adds two field elements together.
    fn add(lhs: &Self, rhs: &Self) -> Self;

    /// Adds the `rhs` field element to the `self` field element, storing the value in `self`.
    fn add_assign(&mut self, rhs: &Self);

    /// Multiplies two field elements together.
    fn mul(lhs: &Self, rhs: &Self) -> Self;

    /// Subtracts `rhs` from `lhs`.
    fn sub(lhs: &Self, rhs: &Self) -> Self;

    /// Computes the multiplicative inverse of a field element.
    fn inverse(&self) -> Option<Self>
    where
        Self: Sized;
}

/// Field Element Generation
pub trait FieldGeneration {
    /// Number of bits of modulus of the field.
    const MODULUS_BITS: usize;

    /// Converts a `u64` value to a field element.
    fn from_u64(elem: u64) -> Self;

    /// Converts from `bits` into a field element in big endian order, returning `None` if `bits`
    /// are out of range.
    fn try_from_bits_be(bits: &[bool]) -> Option<Self>
    where
        Self: Sized;
}

/// Poseidon Permutation Specification
pub trait Specification<COM = ()> {
    /// Field Type used for Permutation State
    type Field;

    /// Field Type used for Constant Parameters
    type ParameterField;

    /// Width of the Permutation
    ///
    /// This number is the total number `t` of field elements in the state which is `F^t`.
    const WIDTH: usize;

    /// Number of Partial Rounds
    const PARTIAL_ROUNDS: usize;

    /// Number of Full Rounds
    ///
    /// The total number of full rounds in the Poseidon permutation, including the first set of full
    /// rounds and then the second set after the partial rounds.
    const FULL_ROUNDS: usize;

    /// Adds two field elements together.
    fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Adds a field element `lhs` with a constant `rhs`
    fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Multiplies two field elements together.
    fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Multiplies a field element `lhs` with a constant `rhs`
    fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Adds the `rhs` field element to `lhs` field element, updating the value in `lhs`
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut COM);

    /// Adds the `rhs` constant to `lhs` field element, updating the value in `lhs`
    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, compiler: &mut COM);

    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);
}

/// Poseidon Internal State
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct State<S, COM = ()>(Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> State<S, COM>
where
    S: Specification<COM>,
{
    /// Builds a new [`State`] from `state`.
    #[inline]
    pub fn new(state: Box<[S::Field]>) -> Self {
        assert_eq!(state.len(), S::WIDTH);
        Self(state)
    }

    /// Returns a slice iterator over the state.
    #[inline]
    pub fn iter(&self) -> slice::Iter<S::Field> {
        self.0.iter()
    }

    /// Returns a mutable slice iterator over the state.
    #[inline]
    pub fn iter_mut(&mut self) -> slice::IterMut<S::Field> {
        self.0.iter_mut()
    }
}

/// Poseidon Permutation
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
pub struct Permutation<S, COM = ()>
where
    S: Specification<COM>,
{
    /// Additive Round Keys
    additive_round_keys: Box<[S::ParameterField]>,

    /// MDS Matrix
    mds_matrix: Box<[S::ParameterField]>,
}

impl<S, COM> Permutation<S, COM>
where
    S: Specification<COM>,
{
    /// Half Number of Full Rounds
    ///
    /// Poseidon Hash first has [`HALF_FULL_ROUNDS`]-many full rounds in the beginning,
    /// followed by [`PARTIAL_ROUNDS`]-many partial rounds in the middle, and finally
    /// [`HALF_FULL_ROUNDS`]-many full rounds at the end.
    ///
    /// [`HALF_FULL_ROUNDS`]: Self::HALF_FULL_ROUNDS
    /// [`PARTIAL_ROUNDS`]: Specification::PARTIAL_ROUNDS
    pub const HALF_FULL_ROUNDS: usize = S::FULL_ROUNDS / 2;

    /// Total Number of Rounds
    pub const ROUNDS: usize = S::FULL_ROUNDS + S::PARTIAL_ROUNDS;

    /// Number of Entries in the MDS Matrix
    pub const MDS_MATRIX_SIZE: usize = S::WIDTH * S::WIDTH;

    /// Total Number of Additive Rounds Keys
    pub const ADDITIVE_ROUND_KEYS_COUNT: usize = Self::ROUNDS * S::WIDTH;

    /// Builds a new [`Permutation`] from `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Specification`].
    #[inline]
    pub fn new(
        additive_round_keys: Box<[S::ParameterField]>,
        mds_matrix: Box<[S::ParameterField]>,
    ) -> Self {
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

    /// Builds a new [`Permutation`] from `additive_round_keys` and `mds_matrix` without
    /// checking their sizes.
    #[inline]
    fn new_unchecked(
        additive_round_keys: Box<[S::ParameterField]>,
        mds_matrix: Box<[S::ParameterField]>,
    ) -> Self {
        Self {
            additive_round_keys,
            mds_matrix,
        }
    }

    /// Returns the additive keys for the given `round`.
    #[inline]
    pub fn additive_keys(&self, round: usize) -> &[S::ParameterField] {
        let start = round * S::WIDTH;
        &self.additive_round_keys[start..start + S::WIDTH]
    }

    /// Computes the MDS matrix multiplication against the `state`.
    #[inline]
    pub fn mds_matrix_multiply(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        let mut next = Vec::with_capacity(S::WIDTH);
        for i in 0..S::WIDTH {
            // NOTE: clippy false-positive: Without `collect`, the two closures in `map` and
            //       `reduce` will have simultaneous `&mut` access to `compiler`. Adding `collect`
            //       allows `map` to be done before `reduce`.
            #[allow(clippy::needless_collect)]
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| S::mul_const(elem, &self.mds_matrix[S::WIDTH * i + j], compiler))
                .collect::<Vec<_>>();
            next.push(
                linear_combination
                    .into_iter()
                    .reduce(|acc, next| S::add(&acc, &next, compiler))
                    .unwrap(),
            );
        }
        mem::swap(&mut next.into_boxed_slice(), &mut state.0);
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    #[inline]
    pub fn full_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_const_assign(elem, &keys[i], compiler);
            S::apply_sbox(elem, compiler);
        }
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    pub fn partial_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_const_assign(elem, &keys[i], compiler);
        }
        S::apply_sbox(&mut state.0[0], compiler);
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes the full permutation without the first round.
    #[inline]
    fn permute_without_first_round(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        for round in 1..Self::HALF_FULL_ROUNDS {
            self.full_round(round, state, compiler);
        }
        for round in Self::HALF_FULL_ROUNDS..(Self::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS) {
            self.partial_round(round, state, compiler);
        }
        for round in
            (Self::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS)..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
        {
            self.full_round(round, state, compiler);
        }
    }

    /// Computes the first round borrowing the `input` and `domain_tag` returning the [`State`]
    /// after the first round. This method does not check that `N + 1 = S::WIDTH`.
    #[inline]
    fn first_round_with_domain_tag_unchecked<const N: usize>(
        &self,
        domain_tag: &S::Field,
        input: [&S::Field; N],
        compiler: &mut COM,
    ) -> State<S, COM> {
        let mut state = Vec::with_capacity(S::WIDTH);
        for (i, point) in iter::once(domain_tag).chain(input).enumerate() {
            let mut elem = S::add_const(point, &self.additive_round_keys[i], compiler);
            S::apply_sbox(&mut elem, compiler);
            state.push(elem);
        }
        let mut state = State(state.into_boxed_slice());
        self.mds_matrix_multiply(&mut state, compiler);
        state
    }
}

impl<S, COM> Decode for Permutation<S, COM>
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
                .map(|_| Decode::decode(&mut reader))
                .collect::<Result<_, _>>()?,
            (0..Self::MDS_MATRIX_SIZE)
                .map(|_| Decode::decode(&mut reader))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl<S, COM> Encode for Permutation<S, COM>
where
    S: Specification<COM>,
    S::ParameterField: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        for key in self.additive_round_keys.iter() {
            key.encode(&mut writer)?;
        }
        for entry in self.mds_matrix.iter() {
            entry.encode(&mut writer)?;
        }
        Ok(())
    }
}

impl<S, COM> PseudorandomPermutation<COM> for Permutation<S, COM>
where
    S: Specification<COM>,
{
    type Domain = State<S, COM>;

    #[inline]
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM) {
        self.full_round(0, state, compiler);
        self.permute_without_first_round(state, compiler);
    }
}

impl<D, S, COM> Sample<D> for Permutation<S, COM>
where
    D: Clone,
    S: Specification<COM>,
    S::ParameterField: Field + FieldGeneration + PartialEq + Sample<D>,
{
    /// Samples random Poseidon parameters.
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
        Self {
            additive_round_keys: generate_round_constants(
                S::WIDTH,
                S::FULL_ROUNDS,
                S::PARTIAL_ROUNDS,
            )
            .into_boxed_slice(),
            mds_matrix: MdsMatrices::generate_mds(S::WIDTH)
                .to_row_major()
                .into_boxed_slice(),
        }
    }
}

/// Poseidon Hasher
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Permutation<S, COM>: Deserialize<'de>, S::Field: Deserialize<'de>",
            serialize = "Permutation<S, COM>: Serialize, S::Field: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Permutation<S, COM>: Clone, S::Field: Clone"),
    Debug(bound = "Permutation<S, COM>: Debug, S::Field: Debug"),
    Eq(bound = "Permutation<S, COM>: Eq, S::Field: Eq"),
    Hash(bound = "Permutation<S, COM>: Hash, S::Field: Hash"),
    PartialEq(bound = "Permutation<S, COM>: PartialEq, S::Field: PartialEq")
)]
pub struct Hasher<S, const ARITY: usize, COM = ()>
where
    S: Specification<COM>,
{
    /// Poseidon Permutation
    permutation: Permutation<S, COM>,

    /// Domain Tag
    domain_tag: S::Field,
}

impl<S, const ARITY: usize, COM> Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
{
    /// Builds a new [`Hasher`] over `permutation` and `domain_tag`.
    #[inline]
    pub fn new(permutation: Permutation<S, COM>, domain_tag: S::Field) -> Self {
        assert_eq!(ARITY + 1, S::WIDTH);
        Self {
            permutation,
            domain_tag,
        }
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
        let mut state = self.permutation.first_round_with_domain_tag_unchecked(
            &self.domain_tag,
            input,
            compiler,
        );
        self.permutation
            .permute_without_first_round(&mut state, compiler);
        state.0.into_vec().take_first()
    }
}

impl<S, const ARITY: usize, COM> Decode for Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
    S::Field: Decode,
    S::ParameterField: Decode<Error = <S::Field as Decode>::Error>,
{
    type Error = <S::Field as Decode>::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(
            Decode::decode(&mut reader)?,
            Decode::decode(&mut reader)?,
        ))
    }
}

impl<S, const ARITY: usize, COM> Encode for Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
    S::Field: Encode,
    S::ParameterField: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.permutation.encode(&mut writer)?;
        self.domain_tag.encode(&mut writer)?;
        Ok(())
    }
}

impl<D, S, const ARITY: usize, COM> Sample<D> for Hasher<S, ARITY, COM>
where
    D: Clone,
    S: Specification<COM>,
    S::Field: Sample<D>,
    S::ParameterField: Field + FieldGeneration + PartialEq + Sample<D>,
{
    /// Samples random Poseidon parameters.
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        // FIXME: Use a proper domain tag sampling method.
        Self::new(rng.sample(distribution.clone()), rng.sample(distribution))
    }
}

/// Arkworks Backend.
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::{
        constraint::arkworks::{Fp, FpVar, R1CS},
        poseidon::FieldGeneration,
    };
    use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
    use ark_r1cs_std::fields::FieldVar;
    use manta_crypto::constraint::Constant;

    /// Compiler Type.
    type Compiler<S> = R1CS<<S as Specification>::Field>;

    /// Poseidon Permutation Specification.
    pub trait Specification {
        /// Field Type
        type Field: PrimeField;

        /// Width of the Permutation
        ///
        /// This number is the total number `t` of field elements in the state which is `F^t`.
        const WIDTH: usize;

        /// Number of Partial Rounds
        const PARTIAL_ROUNDS: usize;

        /// Number of Full Rounds
        ///
        /// The total number of full rounds in the Poseidon permutation, including the first set of
        /// full rounds and then the second set after the partial rounds.
        const FULL_ROUNDS: usize;

        /// S-BOX Exponenet
        const SBOX_EXPONENT: u64;
    }

    impl<F> super::Field for Fp<F>
    where
        F: PrimeField,
    {
        #[inline]
        fn zero() -> Self {
            Self(F::zero())
        }

        #[inline]
        fn is_zero(&self) -> bool {
            self.0 == F::zero()
        }

        #[inline]
        fn one() -> Self {
            Self(F::one())
        }

        #[inline]
        fn add(lhs: &Self, rhs: &Self) -> Self {
            Self(lhs.0 + rhs.0)
        }

        #[inline]
        fn add_assign(&mut self, rhs: &Self) {
            self.0 += rhs.0;
        }

        #[inline]
        fn sub(lhs: &Self, rhs: &Self) -> Self {
            Self(lhs.0 - rhs.0)
        }

        #[inline]
        fn mul(lhs: &Self, rhs: &Self) -> Self {
            Self(lhs.0 * rhs.0)
        }

        #[inline]
        fn inverse(&self) -> Option<Self> {
            self.0.inverse().map(Self)
        }
    }

    impl<F> FieldGeneration for Fp<F>
    where
        F: PrimeField,
    {
        const MODULUS_BITS: usize = F::Params::MODULUS_BITS as usize;

        #[inline]
        fn try_from_bits_be(bits: &[bool]) -> Option<Self> {
            F::from_repr(F::BigInt::from_bits_be(bits)).map(Self)
        }

        #[inline]
        fn from_u64(elem: u64) -> Self {
            Self(F::from(elem))
        }
    }

    impl<S> super::Specification for S
    where
        S: Specification,
    {
        type Field = Fp<S::Field>;
        type ParameterField = Fp<S::Field>;

        const WIDTH: usize = S::WIDTH;
        const FULL_ROUNDS: usize = S::FULL_ROUNDS;
        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            Fp(lhs.0 + rhs.0)
        }

        #[inline]
        fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
            Fp(lhs.0 + rhs.0)
        }

        #[inline]
        fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
            Fp(lhs.0 * rhs.0)
        }

        #[inline]
        fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
            Fp(lhs.0 * rhs.0)
        }

        #[inline]
        fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
            lhs.0 += rhs.0;
        }

        #[inline]
        fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut ()) {
            lhs.0 += rhs.0;
        }

        #[inline]
        fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
            point.0 = point.0.pow(&[Self::SBOX_EXPONENT, 0, 0, 0]);
        }
    }

    impl<S> super::Specification<Compiler<S>> for S
    where
        S: Specification,
    {
        type Field = FpVar<S::Field>;
        type ParameterField = Fp<S::Field>;

        const WIDTH: usize = S::WIDTH;
        const FULL_ROUNDS: usize = S::FULL_ROUNDS;
        const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;

        #[inline]
        fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
            lhs + rhs
        }

        #[inline]
        fn add_const(
            lhs: &Self::Field,
            rhs: &Self::ParameterField,
            _: &mut Compiler<S>,
        ) -> Self::Field {
            lhs + FpVar::Constant(rhs.0)
        }

        #[inline]
        fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
            lhs * rhs
        }

        #[inline]
        fn mul_const(
            lhs: &Self::Field,
            rhs: &Self::ParameterField,
            _: &mut Compiler<S>,
        ) -> Self::Field {
            lhs * FpVar::Constant(rhs.0)
        }

        #[inline]
        fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) {
            *lhs += rhs;
        }

        #[inline]
        fn add_const_assign(
            lhs: &mut Self::Field,
            rhs: &Self::ParameterField,
            _: &mut Compiler<S>,
        ) {
            *lhs += FpVar::Constant(rhs.0)
        }

        #[inline]
        fn apply_sbox(point: &mut Self::Field, _: &mut Compiler<S>) {
            *point = point
                .pow_by_constant(&[Self::SBOX_EXPONENT])
                .expect("Exponentiation is not allowed to fail.");
        }
    }

    impl<S> Constant<Compiler<S>> for super::Permutation<S, Compiler<S>>
    where
        S: Specification,
    {
        type Type = super::Permutation<S>;

        #[inline]
        fn new_constant(this: &Self::Type, compiler: &mut Compiler<S>) -> Self {
            let _ = compiler;
            Self {
                additive_round_keys: this.additive_round_keys.clone(),
                mds_matrix: this.mds_matrix.clone(),
            }
        }
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    /// Tests if [`Poseidon2`](crate::config::Poseidon2) matches the known hash values.
    #[test]
    fn poseidon_hash_matches_known_values() {
        /* TODO: After upgrading to new Poseidon, we have to enable these tests.
        let hasher = Poseidon2::gen(&mut OsRng);
        let inputs = [&Fp(field_new!(Fr, "1")), &Fp(field_new!(Fr, "2"))];
        assert_eq!(
            hasher.hash_untruncated(inputs, &mut ()),
            vec![
                Fp(field_new!(
                    Fr,
                    "1808609226548932412441401219270714120272118151392880709881321306315053574086"
                )),
                Fp(field_new!(
                    Fr,
                    "13469396364901763595452591099956641926259481376691266681656453586107981422876"
                )),
                Fp(field_new!(
                    Fr,
                    "28037046374767189790502007352434539884533225547205397602914398240898150312947"
                )),
            ]
        );
        */
    }
}
