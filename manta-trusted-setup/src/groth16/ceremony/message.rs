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
    groth16::{
        ceremony::{signature::Nonce as _, Ceremony, Nonce, Proof, Signature, SigningKey},
        mpc::State,
    },
    mpc::Challenge,
    utils::BytesRepr,
};
use derivative::Derivative;
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_util::{
    serde,
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    Array,
};
use std::marker::PhantomData;

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
    /// Participant
    pub identifier: C::Identifier,

    /// Message
    pub message: T,

    /// Nonce
    pub nonce: Nonce<C>,

    /// Signature
    pub signature: Signature<C>,
}

impl<T, C> Signed<T, C>
where
    C: Ceremony,
{
    /// Generates a signed message using user's identifier, nonce, and key pair, and increment nonce by 1.
    #[inline]
    pub fn new(
        message: T,
        identifier: C::Identifier,
        nonce: &mut Nonce<C>,
        signing_key: &SigningKey<C>,
    ) -> Result<Self, ()>
    where
        T: Serialize,
    {
        let signature = sign::<_, C::SignatureScheme>(&message, nonce.clone(), signing_key)?;
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
    C: Ceremony,
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
        serialize = "State<C::Pairing>: CanonicalSerialize, Challenge<C>: CanonicalSerialize",
        deserialize = "State<C::Pairing>: CanonicalDeserialize, Challenge<C>: CanonicalDeserialize"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct MPCState<C, const N: usize>
where
    C: Ceremony,
{
    /// State
    pub state: Array<BytesRepr<State<C::Pairing>>, N>,

    /// Challenge
    pub challenge: Array<BytesRepr<Challenge<C>>, N>,

    __: PhantomData<C>,
}

/// Contribute States
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = "State<C::Pairing>: CanonicalSerialize, Proof<C>: CanonicalSerialize",
        deserialize = "State<C::Pairing>: CanonicalDeserialize, Proof<C>: CanonicalDeserialize"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct ContributeState<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// State
    pub state: Array<BytesRepr<State<C::Pairing>>, CIRCUIT_COUNT>,

    /// Proof
    pub proof: Array<BytesRepr<Proof<C>>, CIRCUIT_COUNT>,
}

/// Response for State Sizes
#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct ServerSize<const CIRCUIT_COUNT: usize>(pub Array<StateSize, CIRCUIT_COUNT>);

impl<const CIRCUIT_COUNT: usize> From<Array<StateSize, CIRCUIT_COUNT>>
    for ServerSize<CIRCUIT_COUNT>
{
    fn from(inner: Array<StateSize, CIRCUIT_COUNT>) -> Self {
        ServerSize(inner)
    }
}

/// State Size
pub type StateSize = crate::groth16::mpc::StateSize;
