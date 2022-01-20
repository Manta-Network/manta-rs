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

//! Arkworks Proof System Implementations

use crate::crypto::constraint::arkworks::{SynthesisResult, R1CS};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};

/// Constraint Synthesizer Wrapper
///
/// This wraps an [`R1CS`] constraint system and allows it to be used as a [`ConstraintSynthesizer`]
/// for building proofs using arkworks proof systems.
pub struct ConstraintSynthesizerWrapper<F>(pub R1CS<F>)
where
    F: ark_ff::PrimeField;

impl<F> ConstraintSynthesizer<F> for ConstraintSynthesizerWrapper<F>
where
    F: ark_ff::PrimeField,
{
    #[inline]
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> SynthesisResult {
        let precomputed_cs = self
            .0
            .cs
            .into_inner()
            .expect("We own this constraint system so we can consume it.");
        let mut target_cs = cs
            .borrow_mut()
            .expect("This is given to us to mutate so it can't be borrowed by anyone else.");
        *target_cs = precomputed_cs;
        Ok(())
    }
}

/// Pairing Engine Utilities
pub mod pairing {
    /// BLS-12 Utilities
    pub mod bls12 {
        use crate::crypto::constraint::arkworks::codec::{HasDeserialization, HasSerialization};
        use ark_ec::models::bls12::{g2, Bls12Parameters};
        use ark_ff::Fp2;
        use ark_serialize::{
            CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
        };

        /// Line Evaluation Coefficients
        pub type EllCoeff<F> = (F, F, F);

        /// G2 Prepared Point
        #[derive(derivative::Derivative, CanonicalSerialize, CanonicalDeserialize)]
        #[derivative(Clone, Default, Debug, Eq, PartialEq)]
        pub struct G2Prepared<P>
        where
            P: Bls12Parameters,
        {
            /// Coefficients
            pub ell_coeffs: Vec<EllCoeff<Fp2<P::Fp2Params>>>,

            /// Infinity Flag
            pub infinity: bool,
        }

        impl<P> From<g2::G2Prepared<P>> for G2Prepared<P>
        where
            P: Bls12Parameters,
        {
            #[inline]
            fn from(point: g2::G2Prepared<P>) -> Self {
                Self {
                    ell_coeffs: point.ell_coeffs,
                    infinity: point.infinity,
                }
            }
        }

        impl<P> From<G2Prepared<P>> for g2::G2Prepared<P>
        where
            P: Bls12Parameters,
        {
            #[inline]
            fn from(point: G2Prepared<P>) -> Self {
                Self {
                    ell_coeffs: point.ell_coeffs,
                    infinity: point.infinity,
                }
            }
        }

        /// G2 Prepared Point Reference
        #[derive(derivative::Derivative)]
        #[derivative(Debug, Eq, PartialEq)]
        pub struct G2PreparedRef<'p, P>(pub &'p g2::G2Prepared<P>)
        where
            P: Bls12Parameters;

        impl<'p, P> CanonicalSerialize for G2PreparedRef<'p, P>
        where
            P: Bls12Parameters,
        {
            #[inline]
            fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
            where
                W: Write,
            {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialize(&mut writer)?;
                infinity.serialize(&mut writer)?;
                Ok(())
            }

            #[inline]
            fn serialized_size(&self) -> usize {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialized_size() + infinity.serialized_size()
            }

            #[inline]
            fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
            where
                W: Write,
            {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialize_uncompressed(&mut writer)?;
                infinity.serialize_uncompressed(&mut writer)?;
                Ok(())
            }

            #[inline]
            fn serialize_unchecked<W>(&self, mut writer: W) -> Result<(), SerializationError>
            where
                W: Write,
            {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialize_unchecked(&mut writer)?;
                infinity.serialize_unchecked(&mut writer)?;
                Ok(())
            }

            #[inline]
            fn uncompressed_size(&self) -> usize {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.uncompressed_size() + infinity.uncompressed_size()
            }
        }

        impl<'p, P> From<&'p g2::G2Prepared<P>> for G2PreparedRef<'p, P>
        where
            P: Bls12Parameters,
        {
            #[inline]
            fn from(point: &'p g2::G2Prepared<P>) -> Self {
                Self(point)
            }
        }

        impl<'p, P> From<G2PreparedRef<'p, P>> for &'p g2::G2Prepared<P>
        where
            P: Bls12Parameters,
        {
            #[inline]
            fn from(point: G2PreparedRef<'p, P>) -> Self {
                point.0
            }
        }

        impl<'p, P> HasSerialization<'p> for g2::G2Prepared<P>
        where
            P: Bls12Parameters,
        {
            type Serialize = G2PreparedRef<'p, P>;
        }

        impl<P> HasDeserialization for g2::G2Prepared<P>
        where
            P: Bls12Parameters,
        {
            type Deserialize = G2Prepared<P>;
        }
    }
}

/// Groth16 Proving System
#[cfg(feature = "groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "groth16")))]
pub mod groth16 {
    use super::*;
    use crate::crypto::constraint::arkworks::{
        self,
        codec::{HasDeserialization, HasSerialization},
        SynthesisError,
    };
    use alloc::vec::Vec;
    use ark_crypto_primitives::SNARK;
    use ark_ec::PairingEngine;
    use ark_groth16::{Groth16 as ArkGroth16, PreparedVerifyingKey};
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
    };
    use core::marker::PhantomData;
    use manta_crypto::{
        constraint::ProofSystem,
        rand::{CryptoRng, RngCore, SizedRng},
    };

    pub use ark_groth16::ProvingKey;

    /// Groth16 Proof
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Debug, Default, Eq, PartialEq)]
    pub struct Proof<E>(pub ark_groth16::Proof<E>)
    where
        E: PairingEngine;

    impl<E> scale_codec::Decode for Proof<E>
    where
        E: PairingEngine,
    {
        #[inline]
        fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
        where
            I: scale_codec::Input,
        {
            Ok(Self(
                ark_groth16::Proof::deserialize(arkworks::codec::ScaleCodecReader(input))
                    .map_err(|_| "Deserialization Error")?,
            ))
        }
    }

    impl<E> scale_codec::Encode for Proof<E>
    where
        E: PairingEngine,
    {
        #[inline]
        fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
        where
            Encoder: FnOnce(&[u8]) -> R,
        {
            let mut buffer = Vec::new();
            self.0
                .serialize(&mut buffer)
                .expect("Encoding is not allowed to fail.");
            f(&buffer)
        }
    }

    impl<E> scale_codec::EncodeLike for Proof<E> where E: PairingEngine {}

    /// Proving Context
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Debug, Eq, PartialEq)]
    pub struct ProvingContext<E>(pub ProvingKey<E>)
    where
        E: PairingEngine;

    impl<E> ProvingContext<E>
    where
        E: PairingEngine,
    {
        /// Builds a new [`ProvingContext`] from `proving_key`.
        #[inline]
        pub fn new(proving_key: ProvingKey<E>) -> Self {
            Self(proving_key)
        }
    }

    /// Verifying Context
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Debug, Default)]
    pub struct VerifyingContext<E>(pub PreparedVerifyingKey<E>)
    where
        E: PairingEngine;

    impl<E> CanonicalSerialize for VerifyingContext<E>
    where
        E: PairingEngine,
        for<'s> E::G2Prepared: HasSerialization<'s>,
    {
        #[inline]
        fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
        where
            W: Write,
        {
            let PreparedVerifyingKey {
                vk,
                alpha_g1_beta_g2,
                gamma_g2_neg_pc,
                delta_g2_neg_pc,
            } = &self.0;
            vk.serialize(&mut writer)?;
            alpha_g1_beta_g2.serialize(&mut writer)?;
            <E::G2Prepared as HasSerialization>::Serialize::from(gamma_g2_neg_pc)
                .serialize(&mut writer)?;
            <E::G2Prepared as HasSerialization>::Serialize::from(delta_g2_neg_pc)
                .serialize(&mut writer)?;
            Ok(())
        }

        #[inline]
        fn serialized_size(&self) -> usize {
            let PreparedVerifyingKey {
                vk,
                alpha_g1_beta_g2,
                gamma_g2_neg_pc,
                delta_g2_neg_pc,
            } = &self.0;
            vk.serialized_size()
                + alpha_g1_beta_g2.serialized_size()
                + <E::G2Prepared as HasSerialization>::Serialize::from(gamma_g2_neg_pc)
                    .serialized_size()
                + <E::G2Prepared as HasSerialization>::Serialize::from(delta_g2_neg_pc)
                    .serialized_size()
        }

        #[inline]
        fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
        where
            W: Write,
        {
            let PreparedVerifyingKey {
                vk,
                alpha_g1_beta_g2,
                gamma_g2_neg_pc,
                delta_g2_neg_pc,
            } = &self.0;
            vk.serialize_uncompressed(&mut writer)?;
            alpha_g1_beta_g2.serialize_uncompressed(&mut writer)?;
            <E::G2Prepared as HasSerialization>::Serialize::from(gamma_g2_neg_pc)
                .serialize_uncompressed(&mut writer)?;
            <E::G2Prepared as HasSerialization>::Serialize::from(delta_g2_neg_pc)
                .serialize_uncompressed(&mut writer)?;
            Ok(())
        }

        #[inline]
        fn serialize_unchecked<W>(&self, mut writer: W) -> Result<(), SerializationError>
        where
            W: Write,
        {
            let PreparedVerifyingKey {
                vk,
                alpha_g1_beta_g2,
                gamma_g2_neg_pc,
                delta_g2_neg_pc,
            } = &self.0;
            vk.serialize_unchecked(&mut writer)?;
            alpha_g1_beta_g2.serialize_unchecked(&mut writer)?;
            <E::G2Prepared as HasSerialization>::Serialize::from(gamma_g2_neg_pc)
                .serialize_unchecked(&mut writer)?;
            <E::G2Prepared as HasSerialization>::Serialize::from(delta_g2_neg_pc)
                .serialize_unchecked(&mut writer)?;
            Ok(())
        }

        #[inline]
        fn uncompressed_size(&self) -> usize {
            let PreparedVerifyingKey {
                vk,
                alpha_g1_beta_g2,
                gamma_g2_neg_pc,
                delta_g2_neg_pc,
            } = &self.0;
            vk.uncompressed_size()
                + alpha_g1_beta_g2.uncompressed_size()
                + <E::G2Prepared as HasSerialization>::Serialize::from(gamma_g2_neg_pc)
                    .uncompressed_size()
                + <E::G2Prepared as HasSerialization>::Serialize::from(delta_g2_neg_pc)
                    .uncompressed_size()
        }
    }

    impl<E> CanonicalDeserialize for VerifyingContext<E>
    where
        E: PairingEngine,
        E::G2Prepared: HasDeserialization,
    {
        #[inline]
        fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
        where
            R: Read,
        {
            Ok(Self(PreparedVerifyingKey {
                vk: CanonicalDeserialize::deserialize(&mut reader)?,
                alpha_g1_beta_g2: CanonicalDeserialize::deserialize(&mut reader)?,
                gamma_g2_neg_pc: <E::G2Prepared as HasDeserialization>::Deserialize::deserialize(
                    &mut reader,
                )?
                .into(),
                delta_g2_neg_pc: <E::G2Prepared as HasDeserialization>::Deserialize::deserialize(
                    &mut reader,
                )?
                .into(),
            }))
        }

        #[inline]
        fn deserialize_uncompressed<R>(mut reader: R) -> Result<Self, SerializationError>
        where
            R: Read,
        {
            Ok(Self(PreparedVerifyingKey {
                vk: CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                alpha_g1_beta_g2: CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                gamma_g2_neg_pc:
                    <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_uncompressed(
                        &mut reader,
                    )?
                    .into(),
                delta_g2_neg_pc:
                    <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_uncompressed(
                        &mut reader,
                    )?
                    .into(),
            }))
        }

        #[inline]
        fn deserialize_unchecked<R>(mut reader: R) -> Result<Self, SerializationError>
        where
            R: Read,
        {
            Ok(Self(PreparedVerifyingKey {
                vk: CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                alpha_g1_beta_g2: CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                gamma_g2_neg_pc:
                    <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_unchecked(
                        &mut reader,
                    )?
                    .into(),
                delta_g2_neg_pc:
                    <E::G2Prepared as HasDeserialization>::Deserialize::deserialize_unchecked(
                        &mut reader,
                    )?
                    .into(),
            }))
        }
    }

    /// Arkworks Groth16 Proof System
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Groth16<E>(PhantomData<E>)
    where
        E: PairingEngine;

    impl<E> ProofSystem for Groth16<E>
    where
        E: PairingEngine,
    {
        type ConstraintSystem = R1CS<E::Fr>;
        type PublicParameters = ();
        type ProvingContext = ProvingContext<E>;
        type VerifyingContext = VerifyingContext<E>;
        type Input = Vec<E::Fr>;
        type Proof = Proof<E>;
        type Verification = bool;
        type Error = SynthesisError;

        #[inline]
        fn for_unknown() -> Self::ConstraintSystem {
            Self::ConstraintSystem::for_unknown()
        }

        #[inline]
        fn for_known() -> Self::ConstraintSystem {
            Self::ConstraintSystem::for_known()
        }

        #[inline]
        fn generate_context<R>(
            cs: Self::ConstraintSystem,
            public_parameters: &Self::PublicParameters,
            rng: &mut R,
        ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            let _ = public_parameters;
            let (proving_key, verifying_key) = ArkGroth16::circuit_specific_setup(
                ConstraintSynthesizerWrapper(cs),
                &mut SizedRng(rng),
            )?;
            Ok((
                ProvingContext(proving_key),
                VerifyingContext(ArkGroth16::process_vk(&verifying_key)?),
            ))
        }

        #[inline]
        fn prove<R>(
            cs: Self::ConstraintSystem,
            context: &Self::ProvingContext,
            rng: &mut R,
        ) -> Result<Self::Proof, Self::Error>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            ArkGroth16::prove(
                &context.0,
                ConstraintSynthesizerWrapper(cs),
                &mut SizedRng(rng),
            )
            .map(Proof)
        }

        #[inline]
        fn verify(
            input: &Self::Input,
            proof: &Self::Proof,
            context: &Self::VerifyingContext,
        ) -> Result<Self::Verification, Self::Error> {
            ArkGroth16::verify_with_processed_vk(&context.0, input, &proof.0)
        }
    }
}
