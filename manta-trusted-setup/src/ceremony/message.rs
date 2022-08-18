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
        config::{CeremonyConfig, Nonce, ParticipantIdentifier, PrivateKey, PublicKey, Signature},
        signature::{Nonce as _, SignatureScheme},
        util::{ContributeState, MPCState, StateSize},
    },
    util::AsBytes,
};
use serde::{Deserialize, Serialize};

/// Request for State Sizes
#[derive(Deserialize, Serialize)]
pub struct SizeRequest;

/// Response for State Sizes
#[derive(Clone, Deserialize, Serialize)]
pub struct ServerSize {
    /// Mint State Size
    pub mint: StateSize,

    /// Private Transfer State Size
    pub private_transfer: StateSize,

    /// Reclaim State Size
    pub reclaim: StateSize,
}

/// Query Request
#[derive(Deserialize, Serialize)]
pub struct QueryRequest;

/// Response for [`QueryRequest`]
#[derive(Deserialize, Serialize)]
#[serde(bound(serialize = "", deserialize = "",), deny_unknown_fields)]
pub enum QueryResponse<C>
where
    C: CeremonyConfig,
{
    /// Queue Position
    QueuePosition(usize),

    /// MPC State
    Mpc(AsBytes<MPCState<C, 3>>),
}

/// Contribute Request
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = r"", deserialize = r"",), deny_unknown_fields)]
pub struct ContributeRequest<C, const N: usize>
where
    C: CeremonyConfig,
{
    /// Contribute state including state and proof
    pub contribute_state: AsBytes<ContributeState<C, N>>,
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
    /// Generates a signed message using user's identifier, nonce, and key pair, and increment nonce by 1.
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
        let signature = C::SignatureScheme::sign(&message, nonce, public_key, private_key)?;
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
