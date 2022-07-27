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

use crate::{
    ceremony::{
        coordinator::Coordinator,
        queue::{Identifier, Priority},
        signature::{self, ed_dalek_signatures, HasPublicKey},
    },
    mpc::{Contribute, Types, Verify},
};
use alloc::vec::Vec;
use ark_ec::PairingEngine;
use ark_sapling_mpc_verify::{
    phase_one::{powersoftau::Configuration, sapling::Sapling},
    phase_two,
    utils::SaplingDistribution,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::marker::PhantomData;
use manta_crypto::rand::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::OpenOptions};

/// The MPC
pub struct BlsPhase2Ceremony<E>
where
    E: PairingEngine,
{
    __: PhantomData<E>,
}

impl<E> Default for BlsPhase2Ceremony<E>
where
    E: PairingEngine,
{
    fn default() -> Self {
        Self { __: PhantomData }
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// Byte representation of a public key (to allow Serde to work later)
pub struct BlsPhase2Proof {
    /// `CanonicalSerialize::serialize` of a `phase2::PublicKey<E>`
    proof: Vec<u8>,
}

impl<E> From<phase_two::PublicKey<E>> for BlsPhase2Proof
where
    E: PairingEngine,
{
    fn from(proof: phase_two::PublicKey<E>) -> Self {
        let mut writer = Vec::<u8>::new();
        let _ = CanonicalSerialize::serialize(&proof, &mut writer);
        Self { proof: writer }
    }
}

impl<E> From<BlsPhase2Proof> for phase_two::PublicKey<E>
where
    E: PairingEngine,
{
    fn from(proof: BlsPhase2Proof) -> Self {
        CanonicalDeserialize::deserialize(&proof.proof[..]).unwrap()
    }
}

impl<E> From<&BlsPhase2Proof> for phase_two::PublicKey<E>
where
    E: PairingEngine,
{
    fn from(proof: &BlsPhase2Proof) -> Self {
        CanonicalDeserialize::deserialize(&proof.proof[..]).unwrap()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)] // TODO: I don't understand why default was needed by Server::execute
/// Byte representation of a `MPCParameters` (to allow Serde to work later)
pub struct BlsPhase2State {
    /// `CanonicalSerialize::serialize` of a `phase2::MPCParameters<E>`
    state: Vec<u8>,
}

impl<E> From<phase_two::MPCParameters<E>> for BlsPhase2State
where
    E: PairingEngine,
{
    fn from(state: phase_two::MPCParameters<E>) -> Self {
        let mut writer = Vec::<u8>::new();
        let _ = CanonicalSerialize::serialize(&state, &mut writer);
        Self { state: writer }
    }
}

impl<E> From<BlsPhase2State> for phase_two::MPCParameters<E>
where
    E: PairingEngine,
{
    fn from(state: BlsPhase2State) -> Self {
        CanonicalDeserialize::deserialize(&state.state[..]).unwrap()
    }
}

impl<E> From<&mut BlsPhase2State> for phase_two::MPCParameters<E>
where
    E: PairingEngine,
{
    fn from(state: &mut BlsPhase2State) -> Self {
        CanonicalDeserialize::deserialize(&state.state[..]).unwrap()
    }
}

impl<E> Types for BlsPhase2Ceremony<E>
where
    E: PairingEngine,
{
    type State = BlsPhase2State;
    // type State = phase_two::MPCParameters<E>;

    type Challenge = (); // todo ? the challenge refactoring hasn't been done yet

    type Proof = BlsPhase2Proof;
    // type Proof = phase_two::PublicKey<E>;
}

/// The ceremony for phase 2 with Bls12-381
pub type SaplingBls12Ceremony = BlsPhase2Ceremony<<Sapling as Configuration>::Pairing>;

impl Contribute for SaplingBls12Ceremony {
    type Contribution = (); // todo: change this to a scalar and change contribute method below
                            // phase_two::PrivateKey<<<Sapling as Configuration>::Pairing as PairingEngine>::Fr>;

    fn contribute(
        &self,
        state: &mut Self::State,
        _challenge: &Self::Challenge,
        _contribution: &Self::Contribution,
    ) -> Self::Proof {
        let mut rng = OsRng;
        // Keep in mind the Self::State type here is a byte encoding of MPC Parameters

        let mut mpc =
            phase_two::MPCParameters::<<Sapling as Configuration>::Pairing>::from(state.clone());
        let _digest = mpc.contribute::<SaplingDistribution, _>(&mut rng);

        // Don't forget to change the underlying state
        *state = BlsPhase2State::from(mpc.clone());
        // TODO: Now the proof has been stuck inside the MpcParameters struct, so
        // for now we'll just pull it back out to return it.
        mpc.contributions.clone().last().cloned().unwrap().into()
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
        match phase_two::verify_contribution::<
            SaplingDistribution,
            <Sapling as Configuration>::Pairing,
        >(&last.into(), &next.clone().into())
        {
            Ok(_) => Ok(next),
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
///
pub struct Participant {
    ///
    pub id: ed_dalek_signatures::ContributorPublicKey,
    ///
    pub priority: CeremonyPriority,
    ///
    pub has_contributed: bool,
}

///
#[derive(Clone, Serialize, Deserialize)]
pub enum CeremonyPriority {
    ///
    High,
    ///
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
        state.extend_from_slice(&self.state);
        state.extend_from_slice(b"Public Key:");
        state.extend_from_slice(&public_key.0);

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
        state.extend_from_slice(&self.proof);
        state.copy_from_slice(b"Public Key:");
        state.extend_from_slice(&public_key.0);

        let message = ed_dalek_signatures::Message::from(&state[..]);
        message.verify_integrity(public_key, signature)
    }
}

/// Registry map for participants in this ceremony.
pub type RegistryMap = HashMap<<Participant as Identifier>::Identifier, Participant>;

/// A coordinator for phase2 with Bls12-381, Ed25519 signatures
pub type SaplingBls12Coordinator =
    Coordinator<SaplingBls12Ceremony, Participant, RegistryMap, ed_dalek_signatures::Ed25519, 2>;

#[test]
fn construct_coordinator_test() {
    let mpc_verifier = SaplingBls12Ceremony::default();
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
    use ed_dalek_signatures::{test_keypair, Message};

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
