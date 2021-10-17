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

// FIXME: Move these tests elsewhere since they are rather general.

use crate::{
    accounting::identity::{Root, Utxo, VoidNumber},
    crypto::constraint::arkworks::{constraint_system::SynthesisResult, ArkConstraintSystem},
};
use alloc::vec::Vec;
use ark_crypto_primitives::SNARK;
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_groth16::{Groth16 as ArkGroth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use manta_accounting::asset::{AssetBalance, AssetId};
use manta_crypto::{
    constraint::{Input, ProofSystem},
    rand::{CryptoRng, RngCore, SizedRng},
};

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
        /* TODO[remove]:
        let input = cs
            .cs
            .borrow()
            .ok_or(SynthesisError::MissingCS)?
            .instance_assignment
            .clone();
        */
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

impl<E> Input<AssetId> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetId) {
        input.push(next.0.into());
    }
}

impl<E> Input<AssetBalance> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &AssetBalance) {
        input.push(next.0.into());
    }
}

impl<E> Input<VoidNumber> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &VoidNumber) {
        /* TODO:
        use ark_ff::ToConstraintField;
        input.append(&mut ToConstraintField::to_field_elements(VoidNumber::deserialize(next))
            .expect("Conversion to constraint field elements is not allowed to fail."));
        */
    }
}

impl<E> Input<Root> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &Root) {
        /* TODO:
        use ark_ff::ToConstraintField;
        input.append(&mut ToConstraintField::to_field_elements(Root::deserialize(next))
            .expect("Conversion to constraint field elements is not allowed to fail."));
        */
        todo!()
    }
}

impl<E> Input<Utxo> for Groth16<E>
where
    E: PairingEngine,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &Utxo) {
        /* TODO:
        use ark_ff::ToConstraintField;
        input.append(&mut ToConstraintField::to_field_elements(Utxo::deserialize(next))
            .expect("Conversion to constraint field elements is not allowed to fail."));
        */
        todo!()
    }
}

#[cfg(test)]
mod test {
    use crate::accounting::{
        identity::UtxoSet,
        transfer::{Mint, PrivateTransfer, Reclaim},
    };
    use manta_accounting::transfer::test::{assert_valid_proof, distribution};
    use manta_crypto::{
        rand::{Rand, TrySample},
        set::VerifiedSet,
    };
    use rand::thread_rng;

    /// Tests the generation of proving/verifying keys for [`Mint`].
    #[test]
    fn sample_mint_keys() {
        Mint::sample_context(&mut thread_rng()).unwrap();
    }

    /// Tests the generation of proving/verifying keys for [`PrivateTransfer`].
    #[test]
    fn sample_private_transfer_keys() {
        PrivateTransfer::sample_context(&mut thread_rng()).unwrap();
    }

    /// Tests the generation of proving/verifying keys for [`Reclaim`].
    #[test]
    fn sample_reclaim_keys() {
        Reclaim::sample_context(&mut thread_rng()).unwrap();
    }

    /// Tests the generation of a [`Mint`].
    #[test]
    fn mint() {
        let mut rng = thread_rng();
        let commitment_scheme = rng.gen();
        let mut utxo_set = UtxoSet::new(rng.gen());

        let mint = Mint::try_sample(
            distribution::Transfer {
                commitment_scheme: &commitment_scheme,
                utxo_set: &mut utxo_set,
            },
            &mut rng,
        )
        .unwrap();

        let (proving_key, verifying_key) =
            Mint::generate_context(&commitment_scheme, utxo_set.verifier(), &mut rng).unwrap();

        assert_valid_proof(
            &mint
                .into_post(
                    &commitment_scheme,
                    utxo_set.verifier(),
                    &proving_key,
                    &mut rng,
                )
                .unwrap(),
            &verifying_key,
        );
    }

    /// Tests the generation of a [`PrivateTransfer`].
    #[test]
    fn private_transfer() {
        let mut rng = thread_rng();
        let commitment_scheme = rng.gen();
        let mut utxo_set = UtxoSet::new(rng.gen());

        let private_transfer = PrivateTransfer::try_sample(
            distribution::Transfer {
                commitment_scheme: &commitment_scheme,
                utxo_set: &mut utxo_set,
            },
            &mut rng,
        )
        .unwrap();

        let (proving_key, verifying_key) =
            PrivateTransfer::generate_context(&commitment_scheme, utxo_set.verifier(), &mut rng)
                .unwrap();

        assert_valid_proof(
            &private_transfer
                .into_post(
                    &commitment_scheme,
                    utxo_set.verifier(),
                    &proving_key,
                    &mut rng,
                )
                .unwrap(),
            &verifying_key,
        );
    }

    /// Tests the generation of a [`Reclaim`].
    #[test]
    fn reclaim() {
        let mut rng = thread_rng();
        let commitment_scheme = rng.gen();
        let mut utxo_set = UtxoSet::new(rng.gen());

        let reclaim = Reclaim::try_sample(
            distribution::Transfer {
                commitment_scheme: &commitment_scheme,
                utxo_set: &mut utxo_set,
            },
            &mut rng,
        )
        .unwrap();

        let (proving_key, verifying_key) =
            Reclaim::generate_context(&commitment_scheme, utxo_set.verifier(), &mut rng).unwrap();

        assert_valid_proof(
            &reclaim
                .into_post(
                    &commitment_scheme,
                    utxo_set.verifier(),
                    &proving_key,
                    &mut rng,
                )
                .unwrap(),
            &verifying_key,
        );
    }
}
