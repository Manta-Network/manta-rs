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

use crate::crypto::poseidon::{Field, FieldGeneration, Hasher, Permutation, Specification};
use manta_crypto::{
    hash::ArrayHashFunction,
    rand::{Rand, RngCore, Sample},
};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    vec::VecExt,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

impl<S, const ARITY: usize, COM> Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
{
    /// Builds a new [`Hasher`] over `permutation` and `domain_tag`.
    #[inline]
    pub fn new(permutation: Permutation<S, COM>, domain_tag: S::ParameterField) -> Self {
        assert_eq!(ARITY + 1, S::WIDTH);
        Self {
            permutation,
            // TODO
            // domain_tag: S::from_parameter(T::domain_tag()),
            domain_tag: S::from_parameter(domain_tag),
        }
    }
}

impl<S, const ARITY: usize, COM> Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
{
    /// Computes the hash over `input` in the given `compiler` and returns the untruncated state.
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

impl<S, const ARITY: usize, COM> ArrayHashFunction<ARITY, COM> for Hasher<S, ARITY, COM>
where
    S: Specification<COM>,
{
    type Input = S::Field;
    type Output = S::Field;

    #[inline]
    fn hash(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output {
        self.hash_untruncated(input, compiler).take_first()
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

// trait DomainTag<S, COM = ()>
// where
//     S: Specification<COM>,
// {
//     /// TODO
//     fn domain_tag() -> S::ParameterField;
// }

// TODO
// impl<D, S, T, const ARITY: usize, COM> Sample<D> for Hasher<S, T, ARITY, COM>
impl<D, S, const ARITY: usize, COM> Sample<D> for Hasher<S, ARITY, COM>
where
    D: Clone,
    S: Specification<COM>,
    S::Field: Sample<D>,
    S::ParameterField: Field + FieldGeneration + PartialEq + Sample<D>,
    // TODO
    // T: DomainTag<S, COM>,
{
    /// Samples random Poseidon parameters.
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        // FIXME: Use a proper domain tag sampling method.
        // TODO
        // Self::new(rng.sample(distribution.clone()), T::domain_tag()) // TODO: Should we have a struct DomainTag<S::Field> and implement sample_domain_tag for it?
        Self::new(rng.sample(distribution.clone()), S::sample_domain_tag()) // T::domain_tag()) // TODO: Should we have a struct DomainTag<S::Field> and implement sample_domain_tag for it?
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use crate::{config::Poseidon2, crypto::constraint::arkworks::Fp};
    use ark_bls12_381::Fr;
    use ark_ff::field_new;
    use manta_crypto::rand::{OsRng, Sample};

    /// Tests if [`Poseidon2`](crate::config::Poseidon2) matches the known hash values.
    #[test]
    fn poseidon_hash_matches_known_values() {
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
    }
}
