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
    ceremony::config::{
        CeremonyConfig, Challenge, Nonce, ParticipantIdentifier, Proof, PublicKey, Signature, State,
    },
    util::AsBytes,
};
use serde::{Deserialize, Serialize};

/// Register Request
#[derive(Deserialize, Serialize)]
#[serde(bound(
    serialize = "ParticipantIdentifier<C>: Serialize, PublicKey<C>: Serialize",
    deserialize = "ParticipantIdentifier<C>: Deserialize<'de>, PublicKey<C>: Deserialize<'de>"
))]
pub struct EnqueueRequest<C>
where
    C: CeremonyConfig,
{
    /// Participant
    pub identifier: ParticipantIdentifier<C>,
    /// Public Key
    pub public_key: PublicKey<C>,
}

/// Query MPC State Request
#[derive(Deserialize, Serialize)]
#[serde(bound(
    serialize = "ParticipantIdentifier<C>: Serialize, PublicKey<C>: Serialize",
    deserialize = "ParticipantIdentifier<C>: Deserialize<'de>, PublicKey<C>: Deserialize<'de>"
))]
pub struct QueryMPCStateRequest<C>
where
    C: CeremonyConfig,
{
    /// Participant
    pub identifier: ParticipantIdentifier<C>,
    /// Public Key
    pub public_key: PublicKey<C>,
}

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
#[serde(bound(
    serialize = "ParticipantIdentifier<C>: Serialize, PublicKey<C>: Serialize",
    deserialize = "ParticipantIdentifier<C>: Deserialize<'de>, PublicKey<C>: Deserialize<'de>"
))]
pub struct ContributeRequest<C>
where
    C: CeremonyConfig,
{
    /// Participant
    pub identifier: ParticipantIdentifier<C>,
    /// Public Key
    pub public_key: PublicKey<C>,

    /// State after Contribution
    pub state: AsBytes<State<C>>,

    /// Proof of contribution
    pub proof: AsBytes<Proof<C>>,
}

/// Signed Message
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"T: Serialize, Signature<C>: Serialize, Nonce<C>: Serialize",
        deserialize = "T: Deserialize<'de>, Signature<C>: Deserialize<'de>, Nonce<C>: Deserialize<'de>",
    ),
    deny_unknown_fields
)]
pub struct Signed<T, C>
where
    C: CeremonyConfig,
{
    /// Message
    pub message: T,

    /// Signature
    pub signature: Signature<C>,

    /// Nonce
    pub nonce: Nonce<C>,
}
