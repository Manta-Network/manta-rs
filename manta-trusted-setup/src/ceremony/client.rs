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

//! Asynchronous client for trusted setup.

use crate::{
    ceremony::{
        message::{ContributeRequest, QueryMPCStateRequest, RegisterRequest, Signed},
        queue::{Identifier, Priority},
        server::HasNonce,
        signature,
        signature::SignatureScheme,
    },
    mpc,
    mpc::Types,
    util::AsBytes,
};
use manta_crypto::arkworks::serialize::CanonicalSerialize;
use manta_util::serde::Serialize;
use rand_chacha::rand_core::OsRng;
use std::marker::PhantomData;

/// Client
pub struct Client<S, P>
where
    S: SignatureScheme,
    P: Priority + Identifier + signature::HasPublicKey<PublicKey = S::PublicKey> + HasNonce<S>,
{
    ///
    participant: P,

    ///
    key_pair: (S::PrivateKey, S::PublicKey),

    /// Type Parameter Marker
    __: PhantomData<S>,
}

impl<S, P> Client<S, P>
where
    S: SignatureScheme,
    P: Priority
        + Identifier
        + signature::HasPublicKey<PublicKey = S::PublicKey>
        + HasNonce<S>
        + Serialize,
{
    ///
    pub fn new(participant: P, key_pair: (S::PrivateKey, S::PublicKey)) -> Self {
        Self {
            participant,
            key_pair,
            __: PhantomData,
        }
    }

    ///
    pub fn register(&mut self) -> Signed<RegisterRequest<P>, S::Signature>
    where
        P: Clone,
    {
        self.participant
            .increase_nonce()
            .expect("Increasing nonce should succeed");
        let message = RegisterRequest {
            participant: self.participant.clone(),
        };
        Signed {
            message: message.clone(),
            signature: S::sign(
                message,
                &self.participant.nonce(),
                &self.key_pair.1,
                &self.key_pair.0,
            )
            .expect("Signing should succeed."),
        }
    }

    ///
    pub fn query_mpc_state(&mut self) -> Signed<QueryMPCStateRequest<P>, S::Signature>
    where
        P: Clone,
    {
        self.participant
            .increase_nonce()
            .expect("Increasing nonce should succeed");
        let message = QueryMPCStateRequest {
            participant: self.participant.clone(),
        };
        Signed {
            message: message.clone(),
            signature: S::sign(
                message,
                &self.participant.nonce(),
                &self.key_pair.1,
                &self.key_pair.0,
            )
            .expect("Signing should succeed."),
        }
    }

    ///
    pub fn contribute<V>(
        &mut self,
        hasher: &V::Hasher,
        challenge: &V::Challenge,
        mut state: V::State,
    ) -> Signed<ContributeRequest<P, V>, S::Signature>
    where
        P: Clone,
        V: Types + mpc::Verify + mpc::Contribute,
        V::State: CanonicalSerialize,
        V::Proof: CanonicalSerialize,
        ContributeRequest<P, V>: Clone,
    {
        self.participant
            .increase_nonce()
            .expect("Increasing nonce should succeed");
        let mut rng = OsRng;
        let proof = V::contribute(hasher, challenge, &mut state, &mut rng)
            .expect("Contribute should succeed.");
        let message: ContributeRequest<P, V> = ContributeRequest {
            participant: self.participant.clone(),
            state: AsBytes::from_actual(state),
            proof: AsBytes::from_actual(proof),
        };
        Signed {
            message: message.clone(),
            signature: S::sign(
                message,
                &self.participant.nonce(),
                &self.key_pair.1,
                &self.key_pair.0,
            )
            .expect("Signing should succeed."),
        }
    }
}
