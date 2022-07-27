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

use crate::ceremony::signature::Verify;
use crate::{
    ceremony::{
        queue::{Identifier, Priority},
        signature,
        signature::{ed_dalek_signatures, Sign, SignatureScheme},
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
    type Nonce;

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
///
pub struct JoinQueueRequest<P, S>
where
    P: Identifier + Priority + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
{
    participant: P,
    sig: S::Signature,
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct GetMpcRequest<P, S, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    ///
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
        
        // broken !
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
/// TODO: Can't get the enum version to derive serde
pub struct GetMpcResponse<S, V>
where
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    // response: MpcResponse<V>,
    __: PhantomData<V>,
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

#[derive(Debug)] //, Deserialize, Serialize)]
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
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    ///
    pub participant: P,
    ///
    pub transformed_state: V::State,
    ///
    pub proof: V::Proof,
    ///
    pub sig: S::Signature,
}
