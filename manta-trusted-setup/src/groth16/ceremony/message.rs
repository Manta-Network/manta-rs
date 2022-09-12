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

// FIXME: Use correct serde configuration since we don't assume it's always available

use crate::groth16::{
    ceremony::Ceremony,
    mpc::{Proof, State, StateSize},
};
use manta_crypto::arkworks::pairing::Pairing;
use manta_util::{
    serde::{Deserialize, Serialize},
    BoxArray,
};

/// MPC States
#[derive(Serialize, Deserialize)]
#[serde(
    bound(
        serialize = "C::Challenge: Serialize",
        deserialize = "C::Challenge: Deserialize<'de>",
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct MPCState<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// State
    pub state: BoxArray<State<C>, CIRCUIT_COUNT>,

    /// Challenge
    pub challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
}

/// Ceremony Size
#[derive(Clone, Deserialize, Serialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct CeremonySize<const CIRCUIT_COUNT: usize>(pub BoxArray<StateSize, CIRCUIT_COUNT>);

impl<const CIRCUIT_COUNT: usize> CeremonySize<CIRCUIT_COUNT> {
    /// Checks that each size in `self` matches each [`State`] in `states`.
    #[inline]
    pub fn matches<P>(&self, states: &[State<P>; CIRCUIT_COUNT]) -> bool
    where
        P: Pairing,
    {
        self.0.iter().zip(states).all(|(l, r)| l.matches(&r.0))
    }
}

/// Query Request
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub struct QueryRequest;

/// Response for [`QueryRequest`]
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        deserialize = "MPCState<C, CIRCUIT_COUNT>: Deserialize<'de>",
        serialize = "MPCState<C, CIRCUIT_COUNT>: Serialize"
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
    State(MPCState<C, CIRCUIT_COUNT>),
}

/// Contribute Request
#[derive(Deserialize, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct ContributeRequest<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// State
    pub state: BoxArray<State<C>, CIRCUIT_COUNT>,

    /// Proof
    pub proof: BoxArray<Proof<C>, CIRCUIT_COUNT>,
}
