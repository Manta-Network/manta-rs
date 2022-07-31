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
        signature::SignatureScheme,
        CeremonyError,
    },
    mpc,
};
use core::{fmt::Debug, marker::PhantomData};
use serde::{Deserialize, Serialize};

/// Register Request
#[derive(Debug, Deserialize, Serialize)]
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
    type Signature = <P::PublicKey as signature::Sign<S>>::Signature;

    #[inline]
    fn sign(
        &self,
        domain_tag: &S::DomainTag,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<Self::Signature, CeremonyError> {
        public_key.sign(domain_tag, public_key, private_key)
    }
}

impl<P, S> signature::Verify<S> for RegisterRequest<P>
where
    P: Identifier + Priority + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    P::PublicKey: signature::Verify<S>,
{
    type Signature = <P::PublicKey as signature::Verify<S>>::Signature;

    #[inline]
    fn verify_integrity(
        &self,
        domain_tag: &S::DomainTag,
        public_key: &S::PublicKey,
        signature: &Self::Signature,
    ) -> Result<(), CeremonyError> {
        public_key.verify_integrity(domain_tag, public_key, signature)
    }
}

/// Request to join the contributor queue as `participant`.
#[derive(Debug, Deserialize, Serialize)]
pub struct JoinQueueRequest<P>
where
    P: Identifier + Priority,
{
    /// Participant
    participant: P,
}

/// Signed request to get the MPC state.
#[derive(Debug, Deserialize, Serialize)]
pub struct GetMpcRequest<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    /// Participant
    pub participant: P,
    __: PhantomData<V>,
}

// TODO: need further discussion: with fixed `domain_tag`, if user leaks the signature during the trusted setup
// then someone can mock this `GetMpcRequest` and get the user's position.
impl<P, S, V> signature::Sign<S> for GetMpcRequest<P, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    P::PublicKey: signature::Sign<S>,
{
    type Signature = <P::PublicKey as signature::Sign<S>>::Signature;

    #[inline]
    fn sign(
        &self,
        domain_tag: &S::DomainTag,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<Self::Signature, CeremonyError> {
        // sign the public key
        public_key.sign(domain_tag, public_key, private_key)
    }
}

impl<P, S, V> signature::Verify<S> for GetMpcRequest<P, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    P::PublicKey: signature::Verify<S>,
{
    type Signature = <P::PublicKey as signature::Verify<S>>::Signature;
    fn verify_integrity(
        &self,
        domain_tag: &S::DomainTag,
        public_key: &S::PublicKey,
        signature: &Self::Signature,
    ) -> Result<(), CeremonyError> {
        // verify the public key
        public_key.verify_integrity(domain_tag, public_key, signature)
    }
}

impl<P, V> GetMpcRequest<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    /// Creates a new [`GetMpcRequest`] with the given `participant`.
    pub fn new(participant: P) -> Self {
        Self {
            participant,
            __: PhantomData,
        }
    }
}

/// The response to a `GetMpcRequest` is either a queue position or,
/// if participant is at front of queue, the MPC state.
#[derive(Debug, Deserialize, Serialize)]
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

/// MPC Response for `GetMpcRequest`
#[derive(Debug, Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"V::State: Serialize",
        deserialize = "V::State: Deserialize<'de>",
    ),
    deny_unknown_fields
)]
pub enum MpcResponse<V>
where
    V: mpc::Verify,
{
    ///
    QueuePosition,
    ///
    Mpc(V::State),
}

///
#[derive(Debug, Deserialize, Serialize)]
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

    #[inline]
    fn sign(
        &self,
        domain_tag: &S::DomainTag,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<Self::Signature, CeremonyError> {
        let state_sig = self
            .transformed_state
            .sign(domain_tag, public_key, private_key)?;
        let proof_sig = self.proof.sign(domain_tag, public_key, private_key)?;
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

    #[inline]
    fn verify_integrity(
        &self,
        domain_tag: &S::DomainTag,
        public_key: &S::PublicKey,
        signature: &Self::Signature,
    ) -> Result<(), CeremonyError> {
        let (state_sig, proof_sig) = signature;
        self.transformed_state
            .verify_integrity(domain_tag, public_key, state_sig)?;
        self.proof
            .verify_integrity(domain_tag, public_key, proof_sig)?;
        Ok(())
    }
}
