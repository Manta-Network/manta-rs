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

//! Groth16 Trusted Setup Ceremony Messaging Protocol

use crate::groth16::{
    ceremony::{Ceremony, Round},
    mpc::{Proof, State},
};
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Query Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueryRequest;

/// Response for [`QueryRequest`]
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Round<C>: Deserialize<'de>",
            serialize = "Round<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
pub enum QueryResponse<C>
where
    C: Ceremony,
{
    /// Queue Position
    QueuePosition(u64),

    /// MPC Round State
    State(Round<C>),
}

/// Contribute Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "", serialize = "",),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
pub struct ContributeRequest<C>
where
    C: Ceremony,
{
    /// State
    pub state: Vec<State<C>>,

    /// Proof
    pub proof: Vec<Proof<C>>,
}
