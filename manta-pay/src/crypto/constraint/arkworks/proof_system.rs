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

use crate::crypto::constraint::arkworks::{constraint_system::SynthesisResult, R1CS};
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

/// Groth16 Proving System
#[cfg(feature = "groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "groth16")))]
pub mod groth16 {
    use super::*;
    use crate::crypto::constraint::arkworks::{self, constraint_system::SynthesisError};
    use alloc::vec::Vec;
    use ark_crypto_primitives::SNARK;
    use ark_ec::PairingEngine;
    use ark_groth16::{Groth16 as ArkGroth16, PreparedVerifyingKey, ProvingKey};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use core::marker::PhantomData;
    use manta_crypto::{
        constraint::ProofSystem,
        rand::{CryptoRng, RngCore, SizedRng},
    };
    use scale_codec::{Decode, Encode, EncodeLike};

    /// Groth16 Proof
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Debug, Default, Eq, PartialEq)]
    pub struct Proof<E>(ark_groth16::Proof<E>)
    where
        E: PairingEngine;

    impl<E> Decode for Proof<E>
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

    impl<E> Encode for Proof<E>
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

    impl<E> EncodeLike for Proof<E> where E: PairingEngine {}

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
        type ProvingContext = ProvingKey<E>;
        type VerifyingContext = PreparedVerifyingKey<E>;
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
            Ok((proving_key, ArkGroth16::process_vk(&verifying_key)?))
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
                context,
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
            ArkGroth16::verify_with_processed_vk(context, input, &proof.0)
        }
    }
}
