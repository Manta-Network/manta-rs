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

//! Arkworks Groth16 Implementation

use crate::crypto::constraint::{constraint_system::SynthesisResult, ArkConstraintSystem};
use alloc::vec::Vec;
use ark_crypto_primitives::SNARK;
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_groth16::{Groth16 as ArkGroth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use manta_crypto::constraint::ProofSystem;
use rand::{CryptoRng, RngCore};

/// Arkworks Groth 16 Proof System
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Groth16<E>(PhantomData<E>)
where
    E: PairingEngine;

impl<E> ProofSystem for Groth16<E>
where
    E: PairingEngine,
{
    type ConstraintSystem = ArkConstraintSystem<E::Fr>;

    type ProvingContext = ProvingKey<E>;

    type VerifyingContext = PreparedVerifyingKey<E>;

    type Proof = (Vec<E::Fr>, Proof<E>);

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
        R: CryptoRng + RngCore,
    {
        let (proving_key, verifying_key) =
            ArkGroth16::circuit_specific_setup(ConstraintSynthesizerWrapper(cs), rng)?;
        Ok((proving_key, ArkGroth16::process_vk(&verifying_key)?))
    }

    #[inline]
    fn generate_proof<R>(
        cs: Self::ConstraintSystem,
        context: &Self::ProvingContext,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>
    where
        R: CryptoRng + RngCore,
    {
        let input = cs
            .cs
            .borrow()
            .ok_or(SynthesisError::MissingCS)?
            .instance_assignment
            .clone();
        let proof = ArkGroth16::prove(context, ConstraintSynthesizerWrapper(cs), rng)?;
        Ok((input, proof))
    }

    #[inline]
    fn verify_proof(
        context: &Self::VerifyingContext,
        proof: &Self::Proof,
    ) -> Result<Self::Verification, Self::Error> {
        ArkGroth16::verify_with_processed_vk(context, &proof.0, &proof.1)
    }
}

/// Constraint Synthesizer Wrapper
struct ConstraintSynthesizerWrapper<F>(ArkConstraintSystem<F>)
where
    F: Field;

impl<F> ConstraintSynthesizer<F> for ConstraintSynthesizerWrapper<F>
where
    F: Field,
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

#[cfg(test)]
mod test {
    use super::*;

    /// Tests the generation of proving/verifying contexts.
    #[test]
    fn generate_context() {}

    /// Tests the generation of proofs.
    #[test]
    fn generate_proof() {}

    /// Tests the verification of proofs.
    #[test]
    fn verify_proof() {}
}
