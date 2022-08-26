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
        config::{
            CeremonyConfig, Challenge, Nonce, ParticipantIdentifier, PrivateKey, Proof, Signature,
            State,
        },
        signature::Nonce as _,
    },
    util::AsBytes,
};
use derivative::Derivative;
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_util::{
    serde::{Deserialize, Serialize},
    Array,
};

use super::signature::sign;

/// Query Request
#[derive(Deserialize, Serialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct QueryRequest;

/// Response for [`QueryRequest`]
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = "MPCState<C, CIRCUIT_COUNT>: Serialize",
        deserialize = "MPCState<C, CIRCUIT_COUNT>: Deserialize<'de>"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum QueryResponse<C, const CIRCUIT_COUNT: usize>
where
    C: CeremonyConfig,
{
    /// Queue Position
    QueuePosition(usize),

    /// MPC State
    Mpc(MPCState<C, CIRCUIT_COUNT>),
}

/// Contribute Request
#[derive(Serialize, Deserialize)]
#[serde(
    bound(
        serialize = "ContributeState<C, CIRCUIT_COUNT>: Serialize",
        deserialize = "ContributeState<C, CIRCUIT_COUNT>: Deserialize<'de>"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct ContributeRequest<C, const CIRCUIT_COUNT: usize>
where
    C: CeremonyConfig,
{
    /// Contribute state including state and proof
    pub contribute_state: ContributeState<C, CIRCUIT_COUNT>,
}

/// Signed Message
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"
            ParticipantIdentifier<C>: Serialize,
            T: Serialize,
            Nonce<C>: Serialize,
            Signature<C>: Serialize,
        ",
        deserialize = r"
            ParticipantIdentifier<C>: Deserialize<'de>,
            T: Deserialize<'de>,
            Nonce<C>: Deserialize<'de>,
            Signature<C>: Deserialize<'de>,
        ",
    ),
    crate = "manta_util::serde",
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
    #[inline]
    pub fn new(
        message: T,
        identifier: ParticipantIdentifier<C>,
        nonce: &mut Nonce<C>,
        private_key: &PrivateKey<C>,
    ) -> Result<Self, ()>
    where
        T: Serialize,
    {
        let signature = sign::<_, C::SignatureScheme>(&message, nonce.clone(), private_key);
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

/// MPC States
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = "State<C>: CanonicalSerialize, Challenge<C>: CanonicalSerialize",
        deserialize = "State<C>: CanonicalDeserialize, Challenge<C>: CanonicalDeserialize"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct MPCState<C, const N: usize>
where
    C: CeremonyConfig,
{
    /// State
    pub state: Array<AsBytes<State<C>>, N>,

    /// Challenge
    pub challenge: Array<AsBytes<Challenge<C>>, N>,
}

/// Contribute States
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = "State<C>: CanonicalSerialize, Proof<C>: CanonicalSerialize",
        deserialize = "State<C>: CanonicalDeserialize, Proof<C>: CanonicalDeserialize"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct ContributeState<C, const CIRCUIT_COUNT: usize>
where
    C: CeremonyConfig,
{
    /// State
    pub state: Array<AsBytes<State<C>>, CIRCUIT_COUNT>,

    /// Proof
    pub proof: Array<AsBytes<Proof<C>>, CIRCUIT_COUNT>,
}

/// Response for State Sizes
#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct ServerSize<const CIRCUIT_COUNT: usize>(pub Array<StateSize, CIRCUIT_COUNT>);

/// State Size
#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct StateSize {
    /// Size of gamma_abc_g1 in verifying key
    pub gamma_abc_g1: usize,

    /// Size of a_query, b_g1_query, and b_g2_query which are equal
    pub a_b_g1_b_g2_query: usize,

    /// Size of h_query
    pub h_query: usize,

    /// Size of l_query
    pub l_query: usize,
}
