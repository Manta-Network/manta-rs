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

#[cfg(feature = "groth16")]
use {
    crate::crypto::constraint::arkworks::constraint_system::SynthesisError,
    alloc::vec::Vec,
    ark_crypto_primitives::SNARK,
    ark_groth16::{Groth16 as ArkGroth16, PreparedVerifyingKey, Proof, ProvingKey},
    core::marker::PhantomData,
    manta_crypto::{
        constraint::ProofSystem,
        rand::{CryptoRng, RngCore, SizedRng},
    },
};

/// Constraint Synthesizer Wrapper
struct ConstraintSynthesizerWrapper<F>(R1CS<F>)
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

/// Arkworks Groth16 Proof System
#[cfg(feature = "groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "groth16")))]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Groth16<E>(PhantomData<E>)
where
    E: ark_ec::PairingEngine;

#[cfg(feature = "groth16")]
impl<E> ProofSystem for Groth16<E>
where
    E: ark_ec::PairingEngine,
{
    type ConstraintSystem = R1CS<E::Fr>;

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
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
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
    }

    #[inline]
    fn verify(
        input: &Self::Input,
        proof: &Self::Proof,
        context: &Self::VerifyingContext,
    ) -> Result<Self::Verification, Self::Error> {
        ArkGroth16::verify_with_processed_vk(context, input, proof)
    }
}
