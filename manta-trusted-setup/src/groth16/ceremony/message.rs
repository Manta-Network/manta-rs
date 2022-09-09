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

use crate::groth16::{
    ceremony::{signature::sign, Ceremony, CeremonyError, Challenge, Nonce, Signature, SigningKey},
    mpc::{Proof, State, StateSize},
};
use manta_util::{
    serde::{Deserialize, Serialize},
    BoxArray,
};

/// MPC States
#[derive(Serialize, Deserialize)]
#[serde(
    bound(
        serialize = "Challenge<C>: Serialize",
        deserialize = "Challenge<C>: Deserialize<'de>",
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct MPCState<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// State
    pub state: BoxArray<State<C::Configuration>, CIRCUIT_COUNT>,

    /// Challenge
    pub challenge: BoxArray<Challenge<C>, CIRCUIT_COUNT>,
}

/// Contribute States
#[derive(Serialize, Deserialize)]
#[serde(
    bound(serialize = "", deserialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct ContributeState<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// State
    pub state: BoxArray<State<C::Configuration>, CIRCUIT_COUNT>,

    /// Proof
    pub proof: BoxArray<Proof<C::Configuration>, CIRCUIT_COUNT>,
}

/// Response for State Sizes
#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct ServerSize<const CIRCUIT_COUNT: usize>(pub BoxArray<StateSize, CIRCUIT_COUNT>);

impl<const CIRCUIT_COUNT: usize> From<BoxArray<StateSize, CIRCUIT_COUNT>>
    for ServerSize<CIRCUIT_COUNT>
{
    fn from(inner: BoxArray<StateSize, CIRCUIT_COUNT>) -> Self {
        ServerSize(inner)
    }
}

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
    C: Ceremony,
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
    C: Ceremony,
{
    /// Contribute state including state and proof
    pub contribute_state: ContributeState<C, CIRCUIT_COUNT>,
}

/// Signed Message
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"
            C::Identifier: Serialize,
            T: Serialize,
            Nonce<C>: Serialize,
            Signature<C>: Serialize,
        ",
        deserialize = r"
            C::Identifier: Deserialize<'de>,
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
    C: Ceremony,
{
    /// Message
    pub message: T,

    /// Nonce
    pub nonce: Nonce<C>,

    /// Signature
    pub signature: Signature<C>,

    /// Participant Identifier
    pub identifier: C::Identifier,
}

impl<T, C> Signed<T, C>
where
    C: Ceremony,
{
    /// Generates a signed message with `signing_key` on `message` and `nonce`.
    #[inline]
    pub fn new(
        message: T,
        nonce: &Nonce<C>,
        signing_key: &SigningKey<C>,
        identifier: C::Identifier,
    ) -> Result<Self, CeremonyError<C>>
    where
        T: Serialize,
        Nonce<C>: Clone,
    {
        let signature = match sign::<_, C::SignatureScheme>(signing_key, nonce.clone(), &message) {
            Ok(signature) => signature,
            Err(_) => return Err(CeremonyError::<C>::BadRequest),
        };
        let message = Signed {
            message,
            nonce: nonce.clone(),
            signature,
            identifier,
        };
        Ok(message)
    }
}
