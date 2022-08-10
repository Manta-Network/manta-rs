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

use crate::ceremony::{
    config::{CeremonyConfig, Challenge, Hasher, PrivateKey, Proof, State},
    message::{ContributeRequest, EnqueueRequest, QueryMPCStateRequest, Signed},
};
use manta_crypto::arkworks::serialize::CanonicalSerialize;

/// Client
pub struct Client<C>
where
    C: CeremonyConfig,
{
    /// Participant data that are public
    participant: C::Participant,

    /// Private Key
    private_key: PrivateKey<C>,
}

impl<C> Client<C>
where
    C: CeremonyConfig,
{
    /// Builds a new [`Client`] with `participant` and `private_key`.
    pub fn new(participant: C::Participant, private_key: PrivateKey<C>) -> Self {
        Self {
            participant,
            private_key,
        }
    }

    /// Enqueues a participant into queue on the server.
    pub fn enqueue(&mut self) -> Signed<EnqueueRequest, C>
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

    /// Queries the MPC state of a participant.
    pub fn query_mpc_state(&mut self) -> Signed<QueryMPCStateRequest, C>
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

    /// Contributes to the state on the server.
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
