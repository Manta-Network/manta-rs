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
        message::{ContributeRequest, QueryRequest, Signed},
    },
    mpc::Contribute,
    util::AsBytes,
};
use manta_crypto::{arkworks::serialize::CanonicalSerialize, rand::OsRng};

use super::signature::SignatureScheme;

// TODO: have better response when a user is not at the front of the queue.

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

    /// Queries the server state.
    pub fn query(&mut self) -> Result<Signed<QueryRequest, C>, ()>
    where
        C::Participant: Clone,
        <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::PublicKey: std::fmt::Debug, // TODO: Remove
    {
        Signed::new(
            QueryRequest,
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
        challenge: &[Challenge<C>; 3],
        mut state: [State<C>; 3],
    ) -> Result<Signed<ContributeRequest<C>, C>, ()>
    where
        C::Participant: Clone,
        State<C>: CanonicalSerialize,
        Proof<C>: CanonicalSerialize,
        <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::PublicKey: std::fmt::Debug,
    {
        println!("Start to contribute");
        let mut rng = OsRng;
        let proof0 =
            C::Setup::contribute(hasher, &challenge[0], &mut state[0], &mut rng).ok_or(())?;
        println!("Contributed proof0");
        let proof1 =
            C::Setup::contribute(hasher, &challenge[1], &mut state[1], &mut rng).ok_or(())?;
        println!("Contributed proof1");
        let proof2 =
            C::Setup::contribute(hasher, &challenge[2], &mut state[2], &mut rng).ok_or(())?;
        println!("Contributed proof2");
        let message = ContributeRequest::<C> {
            state0: AsBytes::from_actual(state[0].clone()),
            proof0: AsBytes::from_actual(proof0),
            state1: AsBytes::from_actual(state[1].clone()),
            proof1: AsBytes::from_actual(proof1),
            state2: AsBytes::from_actual(state[2].clone()),
            proof2: AsBytes::from_actual(proof2),
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
