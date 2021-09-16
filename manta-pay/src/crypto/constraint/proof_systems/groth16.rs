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

use crate::crypto::constraint::ArkConstraintSystem;
use alloc::vec::Vec;
use ark_ec::PairingEngine;
use ark_groth16::{
    create_random_proof, generate_random_parameters, verify_proof, PreparedVerifyingKey, Proof,
    ProvingKey,
};
use ark_relations::r1cs::SynthesisError;
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

    type Error = SynthesisError;

    #[inline]
    fn for_unknown() -> Self::ConstraintSystem {
        todo!()
    }

    #[inline]
    fn for_known() -> Self::ConstraintSystem {
        todo!()
    }

    #[inline]
    fn generate_context<R>(
        cs: Self::ConstraintSystem,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        /* TODO:
        let _ = generate_random_parameters(|| {}, rng)?;
        */
        todo!()
    }

    #[inline]
    fn generate_proof<R>(
        cs: Self::ConstraintSystem,
        context: &Self::ProvingContext,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        /* TODO:
        let input = self.cs.borrow().ok_or(())?.instance_assignment;
        let _ = create_random_proof(|| {}, context, &mut rng)?;
        */
        todo!()
    }

    #[inline]
    fn verify_proof(
        context: &Self::VerifyingContext,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        verify_proof(context, &proof.1, &proof.0)
    }
}
