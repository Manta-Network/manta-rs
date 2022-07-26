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
//! Waiting queue for the ceremony.

use crate::ceremony::signature::{HasPublicKey};
use crate::{
    ceremony::{
        coordinator::Coordinator,
        queue::{Identifier, Priority},
        signature::{self,Sign, ed_dalek_signatures},
    },
    mpc::{Contribute, Types, Verify},
};
use ark_ec::PairingEngine;
use ark_sapling_mpc_verify::{
    phase_one::{powersoftau::Configuration, sapling::Sapling},
    phase_two,
    utils::SaplingDistribution,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::marker::PhantomData;
use std::fs::OpenOptions;
use manta_crypto::rand::OsRng;
use std::collections::HashMap;

/// The MPC
pub struct BlsPhase2Ceremony<E>
where
    E: PairingEngine,
{
    __: PhantomData<E>,
}

impl<E> Types for BlsPhase2Ceremony<E>
where
    E: PairingEngine,
{
    type State = phase_two::MPCParameters<E>;

    type Challenge = (); // todo ? the challenge refactoring hasn't been done yet

    type Proof = phase_two::PublicKey<E>;
}

type SaplingBls12Ceremony = BlsPhase2Ceremony<<Sapling as Configuration>::Pairing>;

impl Contribute for SaplingBls12Ceremony {
    type Contribution =
        phase_two::PrivateKey<<<Sapling as Configuration>::Pairing as PairingEngine>::Fr>;

    fn contribute(
        &self,
        state: &mut Self::State,
        _challenge: &Self::Challenge,
        _contribution: &Self::Contribution,
    ) -> Self::Proof {
        let mut rng = OsRng;
        let _digest = state.contribute::<SaplingDistribution, _>(&mut rng);
        // Now the proof has been stuck inside the MpcParameters struct, so
        // for now we'll just pull it back out to return it.
        state.contributions.clone().last().cloned().unwrap()
    }
}

impl Verify for SaplingBls12Ceremony {
    type Error = phase_two::PhaseTwoError;

    fn challenge(&self, _state: &Self::State, _challenge: &Self::Challenge) -> Self::Challenge {}

    fn verify_transform(
        &self,
        last: Self::State,
        next: Self::State,
        _next_challenge: Self::Challenge,
        _proof: Self::Proof,
    ) -> Result<Self::State, Self::Error> {
        match phase_two::verify_contribution::<SaplingDistribution, _>(&last, &next) {
            Ok(_) => Ok(next),
            Err(e) => Err(e),
        }
    }
}

///
pub struct Participant {
    id: ed_dalek_signatures::ContributorPublicKey,
    priority: CeremonyPriority,
    has_contributed: bool,
}

enum CeremonyPriority {
    High,
    Low,
}

impl Priority for Participant {
    fn priority(&self) -> usize {
        match self.priority {
            CeremonyPriority::High => 1,
            CeremonyPriority::Low => 0,
        }
    }
}

impl Identifier for Participant {
    type Identifier = ed_dalek_signatures::ContributorPublicKey;

    fn identifier(&self) -> Self::Identifier {
        self.id
    }
}

impl HasPublicKey for Participant {
    type PublicKey = ed_dalek_signatures::ContributorPublicKey;
    fn public_key(&self) -> Self::PublicKey {
        self.id
    }
}

impl signature::Verify<ed_dalek_signatures::Ed25519> for <SaplingBls12Ceremony as Types>::State {
    fn verify_integrity(
        &self,
        public_key: &<ed_dalek_signatures::Ed25519 as signature::SignatureScheme>::PublicKey,
        signature: &<ed_dalek_signatures::Ed25519 as signature::SignatureScheme>::Signature,
    ) -> Result<(), super::CeremonyError> {
        let mut state = Vec::<u8>::new();
        state.extend_from_slice(b"State Contribution:");
        let _ = self.serialize(&mut state);
        // state.copy_from_slice(b"Public Key:");
        // let _ = public_key.serialize(&mut state);

        let message = ed_dalek_signatures::Message::from(&state[..]);
        message.verify_integrity(public_key, signature)
    }
}

impl signature::Verify<ed_dalek_signatures::Ed25519> for <SaplingBls12Ceremony as Types>::Proof {
    fn verify_integrity(
        &self,
        public_key: &<ed_dalek_signatures::Ed25519 as signature::SignatureScheme>::PublicKey,
        signature: &<ed_dalek_signatures::Ed25519 as signature::SignatureScheme>::Signature,
    ) -> Result<(), super::CeremonyError> {
        let mut state = Vec::<u8>::new();
        state.extend_from_slice(b"Contribution Proof:");
        let _ = self.serialize(&mut state);
        // state.copy_from_slice(b"Public Key:");
        // let _ = public_key.serialize(&mut state);

        let message = ed_dalek_signatures::Message::from(&state[..]);
        message.verify_integrity(public_key, signature)
    }
}

type RegistryMap = HashMap<<Participant as Identifier>::Identifier, Participant>;

type SaplingBls12Coordinator =
    Coordinator<SaplingBls12Ceremony, Participant, RegistryMap, ed_dalek_signatures::Ed25519, 2>;

#[test]
fn construct_coordinator_test() {
    let mpc_verifier = SaplingBls12Ceremony { __: PhantomData };
    let state = default_reclaim_mpc();
    
    let _coordinator = SaplingBls12Coordinator::new(mpc_verifier, state, ());
}

/// Reads from file to get a "raw" version of the parameters derived from
/// the final sapling phase 1 parameters with no contributions made (delta = 1).
pub fn default_reclaim_mpc() -> phase_two::MPCParameters<<Sapling as Configuration>::Pairing> {
    let mut reader = OpenOptions::new()
        .read(true)
        .open("/Users/thomascnorton/Documents/Manta/trusted-setup/phase2_reclaim_raw_mpc")
        .expect("file not found");
    CanonicalDeserialize::deserialize_unchecked(&mut reader).unwrap()
}

#[test]
fn verify_signature_test() {
    use ed_dalek_signatures::{Message, test_keypair};

    let state = default_reclaim_mpc();

    // Sign a message
    let mut message = Vec::<u8>::new();
    message.extend_from_slice(b"State Contribution:");
    CanonicalSerialize::serialize(&state, &mut message).unwrap();
    let message = Message::from(&message[..]);
    let (private_key, public_key) = test_keypair();
    let signature = message.sign(&public_key, &private_key).unwrap();

    // Verify the signature
    crate::ceremony::signature::Verify::verify_integrity(&state, &public_key, &signature).unwrap();
}