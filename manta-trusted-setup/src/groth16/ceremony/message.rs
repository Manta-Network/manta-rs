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

use crate::{
    groth16::{
        ceremony::{Ceremony, Round},
        mpc::{Proof, State, StateSize},
    },
    mpc,
};
use manta_crypto::arkworks::pairing::Pairing;
use manta_util::serde::{Deserialize, Serialize};

/// Ceremony Size Alias
///
/// In the ceremony we always use parallel round structures to support multiple Groth16 circuits at
/// the same time.
pub type CeremonySize = mpc::Parallel<StateSize>;

impl CeremonySize {
    /// Checks that each size in `self` matches each [`State`] in `states`.
    #[inline]
    pub fn matches<P>(&self, states: &[State<P>]) -> bool
    where
        P: Pairing,
    {
        self.len() == states.len() && self.iter().zip(states).all(|(l, r)| l.matches(&r.0))
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
        deserialize = "Round<C>: Deserialize<'de>",
        serialize = "Round<C>: Serialize"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
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
#[derive(Deserialize, Serialize)]
#[serde(
    bound(deserialize = "", serialize = "",),
    crate = "manta_util::serde",
    deny_unknown_fields
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
