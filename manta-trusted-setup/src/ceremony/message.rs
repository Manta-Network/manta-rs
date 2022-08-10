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

//! Messages

use crate::{
    ceremony::{
        config::{
            CeremonyConfig, Challenge, Nonce, ParticipantIdentifier, PrivateKey, Proof, PublicKey,
            Signature, State,
        },
        signature::{Nonce as _, SignatureScheme},
    },
    util::AsBytes,
};
use serde::{Deserialize, Serialize};

/// Enqueue Request
#[derive(Deserialize, Serialize)]
pub struct EnqueueRequest;

/// Query MPC State Request
#[derive(Deserialize, Serialize)]
pub struct QueryMPCStateRequest;

/// MPC Response for [`QueryMPCStateRequest`]
#[derive(Deserialize, Serialize)]
#[serde(bound(serialize = "", deserialize = "",), deny_unknown_fields)]
pub enum QueryMPCStateResponse<C>
where
    C: CeremonyConfig,
{
    /// Queue Position
    QueuePosition(usize),

    /// MPC State
    Mpc(AsBytes<State<C>>, AsBytes<Challenge<C>>),
}

/// Contribute Request
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = r"", deserialize = r"",), deny_unknown_fields)]
pub struct ContributeRequest<C>
where
    C: CeremonyConfig,
{
    /// State after Contribution
    pub state: AsBytes<State<C>>,

    /// Proof of contribution
    pub proof: AsBytes<Proof<C>>,
}

/// Signed Message
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"T: Serialize, Signature<C>: Serialize, Nonce<C>: Serialize, ParticipantIdentifier<C>: Serialize",
        deserialize = r"T: Deserialize<'de>, Signature<C>: Deserialize<'de>, Nonce<C>: Deserialize<'de>, ParticipantIdentifier<C>: Deserialize<'de>",
    ),
    deny_unknown_fields
)]
pub struct Signed<T, C>
where
    C: CeremonyConfig,
{
    /// Participant
    pub identifier: ParticipantIdentifier<C>,

    /// Message
    pub message: T,

    /// Nonce
    pub nonce: Nonce<C>,

    /// Signature
    pub signature: Signature<C>,
}

impl<T, C> Signed<T, C>
where
    C: CeremonyConfig,
{
    /// Generate a signed message using user's identifier, nonce, and key pair, and increment nonce by 1.
    pub fn new(
        message: T,
        identifier: ParticipantIdentifier<C>,
        nonce: &mut Nonce<C>,
        public_key: &PublicKey<C>,
        private_key: &PrivateKey<C>,
    ) -> Result<Self, ()>
    where
        T: Serialize,
    {
        let signature = C::SignatureScheme::sign(&message, &nonce, public_key, private_key)?;
        let message = Signed {
            message,
            identifier,
            nonce: nonce.clone(),
            signature,
        };
        nonce.increment();
        Ok(message)
    }
}
