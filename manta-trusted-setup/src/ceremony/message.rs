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

//! Messages through Network

use crate::{
    ceremony::{
        config::{CeremonyConfig, Nonce, ParticipantIdentifier, PrivateKey, Signature},
        signature::{Nonce as _, SignatureScheme},
        state::{ContributeState, MPCState},
    },
    util::AsBytes,
};
use derivative::Derivative;
use manta_crypto::signature::Sign;
use manta_util::serde::{Deserialize, Serialize};

/// Query Request
#[derive(Deserialize, Serialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct QueryRequest;

/// Response for [`QueryRequest`]
#[derive(Deserialize, Serialize)]
#[serde(
    bound(serialize = "", deserialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
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
#[serde(
    bound(serialize = "", deserialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
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
        serialize = r"
            Signature<C>: Serialize,
            Nonce<C>: Serialize,
            ParticipantIdentifier<C>: Serialize
        ",
        deserialize = r"
            Signature<C>: Deserialize<'de>,
            Nonce<C>: Deserialize<'de>,
            ParticipantIdentifier<C>: Deserialize<'de>
        ",
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Signed<C>
where
    C: CeremonyConfig,
{
    /// Participant
    pub identifier: ParticipantIdentifier<C>,

    /// Message
    pub message: Vec<u8>,

    /// Nonce
    pub nonce: Nonce<C>,

    /// Signature
    pub signature: Signature<C>,
}

impl<C> Signed<C>
where
    C: CeremonyConfig,
{
    /// Generates a signed message using user's identifier, nonce, and key pair, and increment nonce by 1.
    #[inline]
    pub fn new(
        message: Vec<u8>,
        identifier: ParticipantIdentifier<C>,
        nonce: &mut Nonce<C>,
        private_key: &PrivateKey<C>,
    ) -> Result<Self, ()> {
        let signer = C::SignatureScheme::new();
        let signature = signer.sign(
            &private_key,
            &signer.gen_randomness(),
            &(nonce.clone(), message.clone()),
            &mut (),
        );
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

/// Ceremony Error
///
/// # Note
///
/// All errors here are visible to users.
#[derive(PartialEq, Serialize, Deserialize, Derivative)]
#[derivative(Debug(bound = "Nonce<C>: core::fmt::Debug"))]
#[serde(
    bound(
        serialize = "Nonce<C>: Serialize",
        deserialize = "Nonce<C>: Deserialize<'de>",
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum CeremonyError<C>
where
    C: CeremonyConfig,
{
    /// Malformed request that should not come from official client
    BadRequest,

    /// Nonce not in sync, and client needs to update the nonce
    NonceNotInSync(Nonce<C>),

    /// Not Registered
    NotRegistered,

    /// Already Contributed
    AlreadyContributed,

    /// Not Your Turn
    NotYourTurn,

    /// Timed-out
    Timeout,
}
