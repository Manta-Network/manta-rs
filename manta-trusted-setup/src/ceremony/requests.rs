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
        queue::{Identifier, Priority},
        signature,
        signature::{Sign as _, SignatureScheme, Verify as _},
        CeremonyError,
    },
    mpc,
};
use core::{fmt::Debug, marker::PhantomData};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
/// Register Request
pub struct RegisterRequest<P>
where
    P: Identifier + Priority + signature::HasPublicKey,
{
    /// The Participant to register
    pub participant: P,
}

// TODO: Current SignatureScheme is subject to replay attacks.
impl<P, S> signature::Sign<S> for RegisterRequest<P>
where
    P: Identifier + Priority + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    P::PublicKey: signature::Sign<S>,
{
    type Signature = S::Signature;

    fn sign(
        &self,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<S::Signature, CeremonyError> {
        // sign the public key
        todo!()
    }
}

impl<P, S> signature::Verify<S> for RegisterRequest<P>
where
    P: Identifier + Priority + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    P::PublicKey: signature::Verify<S>,
{
    type Signature = S::Signature;

    fn verify_integrity(
        &self,
        public_key: &S::PublicKey,
        signature: &S::Signature,
    ) -> Result<(), CeremonyError> {
        // verify the public key
        todo!()
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// Request to join the contributor queue as `participant`.
pub struct JoinQueueRequest<P>
where
    P: Identifier + Priority,
{
    /// Participant
    participant: P,
}

#[derive(Debug, Deserialize, Serialize)]
/// Signed request to get the MPC state.
pub struct GetMpcRequest<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    /// Participant
    pub participant: P,
    __: PhantomData<(V)>,
}

impl<P, S, V> signature::Sign<S> for GetMpcRequest<P, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
{
    type Signature = S::Signature;

    fn sign(
        &self,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<S::Signature, CeremonyError> {
        // sign the public key
        todo!()
    }
}

impl<P, S, V> signature::Verify<S> for GetMpcRequest<P, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
{
    type Signature = S::Signature;
    fn verify_integrity(
        &self,
        public_key: &S::PublicKey,
        signature: &S::Signature,
    ) -> Result<(), CeremonyError> {
        // verify the public key
        todo!()
    }
}

impl<P, V> GetMpcRequest<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    /// TODO
    pub fn new(participant: P) -> Self {
        Self {
            participant,
            __: PhantomData,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// The response to a `GetMpcRequest` is either a queue position or,
/// if participant is at front of queue, the MPC state.
pub struct GetMpcResponse<V>
where
    V: mpc::Verify,
{
    __: PhantomData<V>, // TODO: Replace this with response: MpcResponse<V>,
}

// TODO: delete when GetMpcResponse is fixed
impl<V> Default for GetMpcResponse<V>
where
    V: mpc::Verify,
{
    fn default() -> Self {
        Self { __: PhantomData }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"V::State: Serialize",
        deserialize = "V::State: Deserialize<'de>",
    ),
    deny_unknown_fields
)]
/// MPC Response for `GetMpcRequest`
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
pub struct ContributeRequest<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    ///
    pub participant: P,
    ///
    pub transformed_state: V::State,
    ///
    pub proof: V::Proof,
}

impl<P, S, V> signature::Sign<S> for ContributeRequest<P, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: Clone + signature::Sign<S>,
    V::Proof: Clone + signature::Sign<S>,
{
    type Signature = (
        <V::State as signature::Sign<S>>::Signature,
        <V::Proof as signature::Sign<S>>::Signature,
    );
    fn sign(
        &self,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<Self::Signature, CeremonyError> {
        let state_sig = self.transformed_state.sign(public_key, private_key)?;
        let proof_sig = self.proof.sign(public_key, private_key)?;
        Ok((state_sig, proof_sig))
    }
}

impl<P, S, V> signature::Verify<S> for ContributeRequest<P, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: Clone + signature::Verify<S>,
    V::Proof: Clone + signature::Verify<S>,
{
    type Signature = (
        <V::State as signature::Verify<S>>::Signature,
        <V::Proof as signature::Verify<S>>::Signature,
    );
    fn verify_integrity(
        &self,
        public_key: &S::PublicKey,
        signature: &Self::Signature,
    ) -> Result<(), CeremonyError> {
        let (state_sig, proof_sig) = signature;
        self.transformed_state
            .verify_integrity(public_key, state_sig)?;
        self.proof.verify_integrity(public_key, proof_sig)?;
        Ok(())
    }
}

// impl<P, S, V> SignedRequest<S> for ContributeRequest<P, S, V>
// where
//     P: Clone + Identifier + signature::HasPublicKey<PublicKey = <S as SignatureScheme>::PublicKey>,
//     S: SignatureScheme,
//     V: mpc::Verify,
//     V::State: Clone + signature::Verify<S>,
//     V::Proof: Clone + signature::Verify<S>,
// {
//     type Data = (<V as mpc::Types>::State, <V as mpc::Types>::Proof, P);
//
//     type Nonce = Vec<u8>;
//
//     fn new(
//         data: &Self::Data,
//         public_key: &S::PublicKey,
//         private_key: &S::PrivateKey,
//     ) -> Result<Self, CeremonyError>
//     where
//         Self: std::marker::Sized,
//     {
//         // First sign the new state
//         let mut message = Self::nonce();
//         message.extend_from_slice(&data.0.state);
//         let message = ed_dalek_signatures::Message::from(&message[..]);
//         let state_sig = message.sign(public_key, private_key)?;
//
//         // Next sign the proof
//         let mut message = Self::nonce();
//         message.extend_from_slice(&data.1.proof);
//         let message = ed_dalek_signatures::Message::from(&message[..]);
//         let proof_sig = message.sign(public_key, private_key)?;
//         Ok(Self {
//             participant: data.2.clone(),
//             transformed_state: data.0.clone(),
//             proof: data.1.clone(),
//             state_sig,
//             proof_sig,
//         })
//     }
//
//     fn check_signatures(
//         &self,
//         public_key: &<ed_dalek_signatures::Ed25519 as SignatureScheme>::PublicKey,
//     ) -> Result<(), CeremonyError> {
//         // Check the signature on the state
//         let mut message = Self::nonce();
//         message.extend_from_slice(&self.transformed_state.state);
//         let message = ed_dalek_signatures::Message::from(&message[..]);
//         message.verify_integrity(public_key, &self.state_sig)?;
//
//         // Check the signature on the proof
//         let mut message = Self::nonce();
//         message.extend_from_slice(&self.proof.proof);
//         let message = ed_dalek_signatures::Message::from(&message[..]);
//         message.verify_integrity(public_key, &self.proof_sig)
//     }
//
//     fn nonce() -> Self::Nonce {
//         let mut nonce = Vec::<u8>::new();
//         nonce.extend_from_slice(b"ContributeRequest");
//         nonce
//     }
// }
