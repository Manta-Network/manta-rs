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
        config::{
            CeremonyConfig, Challenge, Hasher, Nonce, ParticipantIdentifier, PrivateKey, Proof,
            PublicKey, State,
        },
        message::{ContributeRequest, EnqueueRequest, QueryMPCStateRequest, Signed},
    },
    mpc::Contribute,
    util::AsBytes,
};
use manta_crypto::{arkworks::serialize::CanonicalSerialize, rand::OsRng};

/// Client
pub struct Client<C>
where
    C: CeremonyConfig,
{
    /// Public Key
    public_key: PublicKey<C>,

    /// Identifier
    identifier: ParticipantIdentifier<C>,

    /// Current Nonce
    nonce: Nonce<C>,

    /// Private Key
    private_key: PrivateKey<C>,
}

impl<C> Client<C>
where
    C: CeremonyConfig,
{
    /// Builds a new [`Client`] with `participant` and `private_key`.
    pub fn new(
        public_key: PublicKey<C>,
        identifier: ParticipantIdentifier<C>,
        nonce: Nonce<C>,
        private_key: PrivateKey<C>,
    ) -> Self {
        Self {
            public_key,
            identifier,
            nonce,
            private_key,
        }
    }

    /// Generates a request to enqueue this client into the queue on the server.
    pub fn enqueue(&mut self) -> Result<Signed<EnqueueRequest, C>, ()>
    where
        C::Participant: Clone,
    {
        Signed::new(
            EnqueueRequest,
            self.identifier.clone(),
            &mut self.nonce,
            &self.public_key,
            &self.private_key,
        )
    }

    /// Queries the MPC state of a participant.
    pub fn query_mpc_state(&mut self) -> Result<Signed<QueryMPCStateRequest, C>, ()>
    where
        C::Participant: Clone,
    {
        Signed::new(
            QueryMPCStateRequest,
            self.identifier.clone(),
            &mut self.nonce,
            &self.public_key,
            &self.private_key,
        )
    }

    /// Contributes to the state on the server.
    pub fn contribute(
        &mut self,
        hasher: &Hasher<C>,
        challenge: &Challenge<C>,
        mut state: State<C>,
    ) -> Result<Signed<ContributeRequest<C>, C>, ()>
    where
        C::Participant: Clone,
        State<C>: CanonicalSerialize,
        Proof<C>: CanonicalSerialize,
    {
        let mut rng = OsRng;
        let proof = C::Setup::contribute(hasher, challenge, &mut state, &mut rng).ok_or(())?;
        let message = ContributeRequest::<C> {
            state: AsBytes::from_actual(state),
            proof: AsBytes::from_actual(proof),
        };
        Signed::new(
            message,
            self.identifier.clone(),
            &mut self.nonce,
            &self.public_key,
            &self.private_key,
        )
    }

    /// Set Nonce for the client.
    pub fn set_nonce(&mut self, nonce: Nonce<C>) {
        self.nonce = nonce;
    }
}
