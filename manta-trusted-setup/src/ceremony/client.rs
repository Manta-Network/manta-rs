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
        config::{CeremonyConfig, Challenge, Hasher, PrivateKey, Proof, PublicKey, State},
        message::{ContributeRequest, EnqueueRequest, QueryMPCStateRequest, Signed},
        server::HasNonce,
        signature,
        signature::SignatureScheme,
    },
    util::AsBytes,
};
use manta_crypto::arkworks::serialize::CanonicalSerialize;

/// Client
pub struct Client<C>
where
    C: CeremonyConfig,
{
    ///
    participant: C::Participant,

    ///
    key_pair: (PrivateKey<C>, PublicKey<C>),
}

impl<C> Client<C>
where
    C: CeremonyConfig,
{
    ///
    pub fn new(participant: C::Participant, key_pair: (PrivateKey<C>, PublicKey<C>)) -> Self {
        Self {
            participant,
            key_pair,
        }
    }

    ///
    pub fn enqueue(&mut self) -> Signed<EnqueueRequest<C>, C>
    where
        C::Participant: Clone,
    {
        // self.participant
        //     .increase_nonce()
        //     .expect("Increasing nonce should succeed");
        // let message = RegisterRequest {
        //     participant: self.participant.clone(),
        // };
        // Signed {
        //     message: message.clone(),
        //     signature: S::sign(
        //         message,
        //         &self.participant.nonce(),
        //         &self.key_pair.1,
        //         &self.key_pair.0,
        //     )
        //     .expect("Signing should succeed."),
        // }
        todo!()
    }

    ///
    pub fn query_mpc_state(&mut self) -> Signed<QueryMPCStateRequest<C>, C>
    where
        C::Participant: Clone,
    {
        // self.participant
        //     .update_nonce()
        //     .expect("Increasing nonce should succeed");
        // let message = QueryMPCStateRequest {
        //     participant: self.participant.clone(),
        // };
        // Signed {
        //     message: message.clone(),
        //     signature: S::sign(
        //         message,
        //         &self.participant.nonce(),
        //         &self.key_pair.1,
        //         &self.key_pair.0,
        //     )
        //     .expect("Signing should succeed."),
        // }
        todo!()
    }

    ///
    pub fn contribute(
        &mut self,
        hasher: &Hasher<C>,
        challenge: &Challenge<C>,
        mut state: State<C>,
    ) -> Signed<ContributeRequest<C>, C>
    where
        C::Participant: Clone,
        State<C>: CanonicalSerialize,
        Proof<C>: CanonicalSerialize,
        ContributeRequest<C>: Clone,
    {
        // todo: update nonce
        // let mut rng = OsRng;
        // let proof = V::contribute(hasher, challenge, &mut state, &mut rng)
        //     .expect("Contribute should succeed.");
        // let message: ContributeRequest<P, V> = ContributeRequest {
        //     participant: self.participant.clone(),
        //     state: AsBytes::from_actual(state),
        //     proof: AsBytes::from_actual(proof),
        // };
        // Signed {
        //     message: message.clone(),
        //     signature: S::sign(
        //         message,
        //         &self.participant.nonce(),
        //         &self.key_pair.1,
        //         &self.key_pair.0,
        //     )
        //     .expect("Signing should succeed."),
        // }
        todo!()
    }
}
