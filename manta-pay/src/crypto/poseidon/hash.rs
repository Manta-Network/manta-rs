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

//! Poseidon Hash Implementation

use crate::crypto::poseidon::{
    Field, FieldGeneration, ParameterFieldType, Permutation, Specification,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_crypto::{
    eclair::alloc::{Allocate, Const, Constant},
    hash::ArrayHashFunction,
    rand::{Rand, RngCore, Sample},
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    vec::VecExt,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Domain Tag
pub trait DomainTag<T>
where
    T: ParameterFieldType,
{
    /// Generates domain tag as a constant parameter.
    fn domain_tag() -> T::ParameterField;
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
pub struct Hasher<S, T, const ARITY: usize, COM = ()>
where
    S: Specification<COM>,
    T: DomainTag<S>,
{
    /// Poseidon Permutation
    permutation: Permutation<S, COM>,

    /// Domain Tag
    domain_tag: S::Field,

    /// Type Parameter Marker
    __: PhantomData<T>,
}

impl<S, T, const ARITY: usize, COM> Hasher<S, T, ARITY, COM>
where
    S: Specification<COM>,
    T: DomainTag<S>,
{
    /// Builds a new [`Hasher`] over `permutation` and `domain_tag` without checking that
    /// `ARITY + 1 == S::WIDTH`.
    #[inline]
    fn new_unchecked(permutation: Permutation<S, COM>, domain_tag: S::Field) -> Self {
        Self {
            permutation,
            domain_tag,
            __: PhantomData,
        }
    }

    /// Builds a new [`Hasher`] over `permutation` and `domain_tag`.
    #[inline]
    pub fn new(permutation: Permutation<S, COM>, domain_tag: S::Field) -> Self {
        assert_eq!(ARITY + 1, S::WIDTH);
        Self::new_unchecked(permutation, domain_tag)
    }

    /// Builds a new [`Hasher`] over `permutation` using `T` to generate the domain tag.
    #[inline]
    pub fn from_permutation(permutation: Permutation<S, COM>) -> Self {
        Self::new(permutation, S::from_parameter(T::domain_tag()))
    }

    /// Computes the hash over `input` in the given `compiler` and returns the untruncated state.
    #[inline]
    pub fn hash_untruncated(&self, input: [&S::Field; ARITY], compiler: &mut COM) -> Vec<S::Field> {
        let mut state = self.permutation.first_round_with_domain_tag_unchecked(
            &self.domain_tag,
            input,
            compiler,
        );
        self.permutation
            .permute_without_first_round(&mut state, compiler);
        state.0.into_vec()
    }
}

impl<S, T, const ARITY: usize, COM> Constant<COM> for Hasher<S, T, ARITY, COM>
where
    S: Specification<COM> + Constant<COM>,
    S::Type: Specification<ParameterField = Const<S::ParameterField, COM>>,
    S::ParameterField: Constant<COM>,
    T: DomainTag<S> + Constant<COM>,
    T::Type: DomainTag<S::Type>,
{
    type Type = Hasher<S::Type, T::Type, ARITY>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::from_permutation(this.permutation.as_constant(compiler))
    }
}

impl<S, T, const ARITY: usize, COM> ArrayHashFunction<ARITY, COM> for Hasher<S, T, ARITY, COM>
where
    S: Specification<COM>,
    T: DomainTag<S>,
{
    type Input = S::Field;
    type Output = S::Field;

    #[inline]
    fn hash(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output {
        self.hash_untruncated(input, compiler).take_first()
    }
}

impl<S, T, const ARITY: usize, COM> Decode for Hasher<S, T, ARITY, COM>
where
    S: Specification<COM>,
    S::Field: Decode,
    S::ParameterField: Decode<Error = <S::Field as Decode>::Error>,
    T: DomainTag<S>,
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

impl<S, T, const ARITY: usize, COM> Encode for Hasher<S, T, ARITY, COM>
where
    S: Specification<COM>,
    S::Field: Encode,
    S::ParameterField: Encode,
    T: DomainTag<S>,
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

impl<D, S, T, const ARITY: usize, COM> Sample<D> for Hasher<S, T, ARITY, COM>
where
    S: Specification<COM>,
    S::ParameterField: Field + FieldGeneration + Sample<D>,
    T: DomainTag<S>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::from_permutation(rng.sample(distribution))
    }
}

/* TODO: After upgrading to new Poseidon, we have to enable these tests.
/// Testing Suite
#[cfg(test)]
mod test {
    use crate::{config::Poseidon2, crypto::constraint::arkworks::Fp};
    use ark_bls12_381::Fr;
    use manta_crypto::{
        arkworks::ff::field_new,
        rand::{OsRng, Sample},
    };

    /// Tests if [`Poseidon2`](crate::config::Poseidon2) matches hardcoded sage outputs.
    #[test]
    fn poseidon_hash_matches_known_values() {
        let hasher = Poseidon2::gen(&mut OsRng);
        let inputs = [&Fp(field_new!(Fr, "1")), &Fp(field_new!(Fr, "2"))];
        assert_eq!(
            hasher.hash_untruncated(inputs, &mut ()),
            include!("permutation_hardcoded_test/width3")
        );
    }
}
*/

/// Testing Suite
#[cfg(test)]
mod test {
    use crate::{
        config::{Poseidon2, Poseidon4},
        crypto::constraint::arkworks::Fp,
    };
    use ark_bls12_381::FrParameters;
    use manta_crypto::{
        arkworks::ff::Fp256,
        hash::ArrayHashFunction,
        rand::{OsRng, Rand},
    };

    /// Field Element Type
    type FieldElement = Fp<Fp256<FrParameters>>;

    /// Number of randomly generated input tuples for the collision resistance tests
    /// 
    /// # Note
    /// 
    /// The following tests are expected to break at the 2^128 mark due to 
    /// the birthday attack
    const NUMBER_OF_TRIES: usize = 10000;

    /// Tests Poseidon with arity 2 as a `Hasher` for collision resistance.
    #[test]
    fn poseidon2_collision_resistance() {
        let mut rng = OsRng;
        let compiler = &mut ();
        let poseidon2: Poseidon2 = rng.gen();
        let mut image_vector: Vec<FieldElement> = Vec::with_capacity(NUMBER_OF_TRIES);
        for _ in 0..NUMBER_OF_TRIES {
            let input_1 = rng.gen::<_, FieldElement>();
            let input_2 = rng.gen::<_, FieldElement>();
            let image = poseidon2.hash(
                [
                    &input_1,
                    &input_2,
                ],
                compiler,
            );
            assert!(!image_vector.iter().any(|x| *x == image));
            image_vector.push(image);
        }
    }

     /// Tests Poseidon with arity 4 as a `Hasher` for collision resistance.
     #[test]
     fn poseidon4_collision_resistance() {
         let mut rng = OsRng;
         let compiler = &mut ();
         let poseidon4: Poseidon4 = rng.gen();
         let mut image_vector: Vec<FieldElement> = Vec::with_capacity(NUMBER_OF_TRIES);
         for _ in 0..NUMBER_OF_TRIES {
             let input_1 = rng.gen::<_, FieldElement>();
             let input_2 = rng.gen::<_, FieldElement>();
             let input_3 = rng.gen::<_, FieldElement>();
             let input_4 = rng.gen::<_, FieldElement>();
             let image = poseidon4.hash(
                 [
                     &input_1,
                     &input_2,
                     &input_3,
                     &input_4,
                 ],
                 compiler,
             );
             assert!(!image_vector.iter().any(|x| *x == image));
             image_vector.push(image);
         }
     }
}
