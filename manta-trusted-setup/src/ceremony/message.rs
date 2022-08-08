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
    ceremony::{queue::Identifier, signature::SignatureScheme},
    mpc,
    util::AsBytes,
};
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

/// Register Request
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterRequest<P> {
    /// Participant
    pub participant: P,
}

/// Query MPC State Request
#[derive(Debug, Deserialize, Serialize)]
pub struct QueryMPCStateRequest<P> {
    /// Participant
    pub participant: P,
}

impl<P> QueryMPCStateRequest<P> {
    /// Creates a new [`GetMpcRequest`] with the given `participant`.
    pub fn new(participant: P) -> Self {
        Self { participant }
    }
}

/// MPC Response for [`QueryMPCStateRequest`]
#[derive(Debug, Deserialize, Serialize)]
#[serde(bound(serialize = "", deserialize = "",), deny_unknown_fields)]
pub enum QueryMPCStateResponse<V>
where
    V: mpc::Verify,
{
    /// Queue Position
    QueuePosition(usize),

    /// MPC State
    Mpc(AsBytes<V::State>, AsBytes<V::Challenge>),
}

/// Contribute Request
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    bound(serialize = "P: Serialize", deserialize = "P: Deserialize<'de>",),
    deny_unknown_fields
)]
pub struct ContributeRequest<P, V>
where
    P: Identifier,
    V: mpc::Verify,
{
    /// Participant
    pub participant: P,

    /// State after Contribution
    pub state: AsBytes<V::State>,

    /// Proof of contribution
    pub proof: AsBytes<V::Proof>,
}

/// Signed Message
#[derive(Debug, Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"T: Serialize, S: Serialize",
        deserialize = "T: Deserialize<'de>, S: Deserialize<'de>",
    ),
    deny_unknown_fields
)]
pub struct Signed<T, S> {
    /// Message
    pub message: T,

    /// Signature
    pub signature: S,
}