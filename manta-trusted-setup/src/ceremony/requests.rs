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
//! Registry for the ceremony.

use crate::{
    ceremony::{
        bls_server::SaplingBls12Ceremony,
        queue::{Identifier, Priority},
        signature,
        signature::{ed_dalek_signatures, Sign, SignatureScheme, Verify},
        CeremonyError,
    },
    mpc,
};
use core::{fmt::Debug, marker::PhantomData};
use serde::{Deserialize, Serialize};

/// Signed requests from client to server.
pub trait SignedRequest<S>
where
    S: SignatureScheme,
{
    /// Data to sign, such as a proof of contribution.
    type Data: Clone;
    /// Nonce specific to this request
    type Nonce; // TODO? Maybe "Nonce" is the wrong term, maybe this is a domain tag?

    /// Computes signatures of `Data` and assembles data and
    /// signatures into a request. This should use the nonce.
    fn form_request(
        data: &Self::Data,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<Self, CeremonyError>
    where
        Self: std::marker::Sized;

    /// Checks all signatures in a request.
    fn check_signatures(&self, public_key: &S::PublicKey) -> Result<(), CeremonyError>;

    /// Define a nonce to use for requests of this type
    fn nonce() -> Self::Nonce;
}

#[derive(Debug, Deserialize, Serialize)]
/// Only for testing
pub struct RegisterRequest<P>
where
    P: Identifier + Priority + signature::HasPublicKey,
{
    /// The Participant to register
    pub participant: P,
}

#[derive(Debug, Deserialize, Serialize)]
/// Signed request to join the contributor queue as `participant`.
pub struct JoinQueueRequest<P, S>
where
    P: Identifier + Priority + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
{
    /// Participant
    participant: P,
    /// Signature
    sig: S::Signature,
}

#[derive(Debug, Deserialize, Serialize)]
/// Signed request to get the MPC state.
pub struct GetMpcRequest<P, S, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    /// Participant
    pub participant: P,
    /// Signature of the message "GetMpcRequest"
    pub sig: S::Signature,
    __: PhantomData<V>,
}

impl<P, S, V> GetMpcRequest<P, S, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    ///
    pub fn new(participant: P, sig: S::Signature) -> Self {
        Self {
            participant,
            sig,
            __: PhantomData,
        }
    }
}

impl<P, V> SignedRequest<ed_dalek_signatures::Ed25519>
    for GetMpcRequest<P, ed_dalek_signatures::Ed25519, V>
where
    P: Clone
        + Identifier
        + signature::HasPublicKey<
            PublicKey = <ed_dalek_signatures::Ed25519 as SignatureScheme>::PublicKey,
        >,
    V: mpc::Verify,
    V::State: signature::Verify<ed_dalek_signatures::Ed25519>,
    V::Proof: signature::Verify<ed_dalek_signatures::Ed25519>,
{
    type Data = P;

    type Nonce = Vec<u8>; // todo : what's a better choice here?

    fn form_request(
        data: &Self::Data,
        public_key: &<ed_dalek_signatures::Ed25519 as SignatureScheme>::PublicKey,
        private_key: &<ed_dalek_signatures::Ed25519 as SignatureScheme>::PrivateKey,
    ) -> Result<Self, CeremonyError> {
        // These requests will be signed with just the participant's public key
        let mut message = Self::nonce();
        message.extend_from_slice(&public_key.0);
        let message = ed_dalek_signatures::Message::from(&message[..]);
        let signature = message.sign(public_key, private_key)?;
        Ok(Self::new(data.clone(), signature))
    }

    fn check_signatures(
        &self,
        public_key: &<ed_dalek_signatures::Ed25519 as SignatureScheme>::PublicKey,
    ) -> Result<(), CeremonyError> {
        // These requests should have been signed with just the participant's public key
        let mut message = Self::nonce();
        message.extend_from_slice(&public_key.0);
        let message = ed_dalek_signatures::Message::from(&message[..]);
        message.verify_integrity(public_key, &self.sig)
    }

    fn nonce() -> Self::Nonce {
        let mut nonce = Vec::<u8>::new();
        nonce.extend_from_slice(b"GetMpcRequest");
        nonce
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// The response to a `GetMpcRequest` is either a queue position or, 
/// if participant is at front of queue, the MPC state.
pub struct GetMpcResponse<S, V>
where
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    __: PhantomData<V>, // TODO: Replace this with response: MpcResponse<V>,
    ___: PhantomData<S>,
}

// TODO: delete when GetMpcResponse is fixed
impl<S, V> Default for GetMpcResponse<S, V>
where
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    fn default() -> Self {
        Self {
            __: PhantomData,
            ___: PhantomData,
        }
    }
}

// #[derive(Debug, Deserialize, Serialize)]
#[derive(Debug)]
///
pub enum MpcResponse<V>
where
    V: mpc::Verify,
{
    ///
    QueuePosition,
    ///
    Mpc(V::State),
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct ContributeRequest<P, S, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: Clone + signature::Verify<S>,
    V::Proof: Clone + signature::Verify<S>,
{
    ///
    pub participant: P,
    ///
    pub transformed_state: V::State,
    ///
    pub proof: V::Proof,
    ///
    pub state_sig: S::Signature,
    ///
    pub proof_sig: S::Signature,
}

impl<P> SignedRequest<ed_dalek_signatures::Ed25519>
    for ContributeRequest<P, ed_dalek_signatures::Ed25519, SaplingBls12Ceremony>
where
    P: Clone
        + Identifier
        + signature::HasPublicKey<
            PublicKey = <ed_dalek_signatures::Ed25519 as SignatureScheme>::PublicKey,
        >,
{
    type Data = (
        <SaplingBls12Ceremony as mpc::Types>::State,
        <SaplingBls12Ceremony as mpc::Types>::Proof,
        P,
    );

    type Nonce = Vec<u8>;

    fn form_request(
        data: &Self::Data,
        public_key: &<ed_dalek_signatures::Ed25519 as SignatureScheme>::PublicKey,
        private_key: &<ed_dalek_signatures::Ed25519 as SignatureScheme>::PrivateKey,
    ) -> Result<Self, CeremonyError>
    where
        Self: std::marker::Sized,
    {
        // First sign the new state
        let mut message = Self::nonce();
        message.extend_from_slice(&data.0.state);
        let message = ed_dalek_signatures::Message::from(&message[..]);
        let state_sig = message.sign(public_key, private_key)?;

        // Next sign the proof
        let mut message = Self::nonce();
        message.extend_from_slice(&data.1.proof);
        let message = ed_dalek_signatures::Message::from(&message[..]);
        let proof_sig = message.sign(public_key, private_key)?;
        Ok(Self {
            participant: data.2.clone(),
            transformed_state: data.0.clone(),
            proof: data.1.clone(),
            state_sig,
            proof_sig,
        })
    }

    fn check_signatures(
        &self,
        public_key: &<ed_dalek_signatures::Ed25519 as SignatureScheme>::PublicKey,
    ) -> Result<(), CeremonyError> {
        // Check the signature on the state
        let mut message = Self::nonce();
        message.extend_from_slice(&self.transformed_state.state);
        let message = ed_dalek_signatures::Message::from(&message[..]);
        message.verify_integrity(public_key, &self.state_sig)?;

        // Check the signature on the proof
        let mut message = Self::nonce();
        message.extend_from_slice(&self.proof.proof);
        let message = ed_dalek_signatures::Message::from(&message[..]);
        message.verify_integrity(public_key, &self.proof_sig)
    }

    fn nonce() -> Self::Nonce {
        let mut nonce = Vec::<u8>::new();
        nonce.extend_from_slice(b"ContributeRequest");
        nonce
    }
}
