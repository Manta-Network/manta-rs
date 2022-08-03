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

//! Request Tools

use crate::{
    ceremony::{
        queue::{Identifier, Priority},
        signature::{HasPublicKey, SignatureScheme},
        CeremonyError,
    },
    mpc,
};
use core::{fmt::Debug, marker::PhantomData};
use serde::{Deserialize, Serialize};

/// Register Request
#[derive(Debug, Deserialize, Serialize)]
pub struct Register<P>
where
    P: Identifier + Priority + HasPublicKey,
{
    /// Participant Information
    pub participant: P,
}

/// Query MPC State with Signature
#[derive(Debug, Deserialize, Serialize)]
pub struct QueryMPCState<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    /// Participant
    pub participant: P,

    /// Type Parameter Marker
    __: PhantomData<V>,
}

impl<P, V> QueryMPCState<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    /// Creates a new [`GetMpcRequest`] with the given `participant`.
    pub fn new(participant: P) -> Self {
        Self {
            participant,
            __: PhantomData,
        }
    }
}

/// The response to a `QueryMPCState` is either a queue position or,
/// if participant is at front of queue, the MPC state.
#[derive(Debug, Deserialize, Serialize)]
pub struct GetMpcResponse<V>
where
    V: mpc::Verify,
{
    __: PhantomData<V>, // TODO: Replace this with response: MpcResponse<V>,
}

// TODO: delete when GetMpcResponse is fixed
impl<V> Default for GetMpcResponse<V>
where
    V: mpc::Verify,
{
    fn default() -> Self {
        Self { __: PhantomData }
    }
}

/// MPC Response for `GetMpcRequest`
#[derive(Debug, Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"V::State: Serialize",
        deserialize = "V::State: Deserialize<'de>",
    ),
    deny_unknown_fields
)]
pub enum MpcResponse<V>
where
    V: mpc::Verify,
{
    ///
    QueuePosition,
    ///
    Mpc(V::State),
}

///
#[derive(Debug, Deserialize, Serialize)]
pub struct ContributeRequest<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    ///
    pub participant: P,

    ///
    pub transformed_state: V::State,

    ///
    pub proof: V::Proof,
}
