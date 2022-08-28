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

//! Groth16 Trusted Setup Ceremony Coordinator

use crate::{
    groth16::{
        ceremony::{registry::Registry, Ceremony, Participant},
        mpc::StateSize,
    },
    mpc::{Challenge, Proof, State},
};
use manta_util::{
    collections::vec_deque::MultiVecDeque,
    serde::{Deserialize, Serialize},
    time::lock::Timed,
    Array, BoxArray,
};

/// Proof Array Type
pub type ProofArray<C, const N: usize> = BoxArray<Proof<C>, N>;

/// State Array Type
pub type StateArray<C, const N: usize> = BoxArray<State<C>, N>;

/// Challenge Array Type
pub type ChallengeArray<C, const N: usize> = BoxArray<Challenge<C>, N>;

/// Participant Queue Type
pub type Queue<C, const LEVEL_COUNT: usize> =
    MultiVecDeque<<C as Ceremony>::Identifier, LEVEL_COUNT>;

/// Ceremony Coordinator
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        deserialize = r"
            R: Deserialize<'de>,
            Queue<C, LEVEL_COUNT>: Deserialize<'de>,
            C::Identifier: Deserialize<'de>,
            State<C>: Deserialize<'de>,
            Challenge<C>: Deserialize<'de>,
            Proof<C>: Deserialize<'de>,
            C::Participant: Deserialize<'de>,
        ",
        serialize = r"
            R: Serialize,
            Queue<C, LEVEL_COUNT>: Serialize,
            C::Identifier: Serialize,
            State<C>: Serialize,
            Challenge<C>: Serialize,
            Proof<C>: Serialize,
            C::Participant: Serialize,
        "
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Coordinator<C, R, const CIRCUIT_COUNT: usize, const LEVEL_COUNT: usize>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Participant Registry
    registry: R,

    /// Participant Queue
    queue: Queue<C, LEVEL_COUNT>,

    /// Participant Lock
    participant_lock: Timed<Option<C::Identifier>>,

    /// State
    state: StateArray<C, CIRCUIT_COUNT>,

    /// Challenge
    challenge: ChallengeArray<C, CIRCUIT_COUNT>,

    /// Latest Contributor
    ///
    /// This participant was the last one to perform a successful contribution to the ceremony.
    latest_contributor: Option<C::Participant>,

    /// Latest Proof
    latest_proof: Option<ProofArray<C, CIRCUIT_COUNT>>,

    /// State Sizes
    size: Array<StateSize, CIRCUIT_COUNT>,

    /// Current Round Number
    round: usize,
}

impl<C, R, const CIRCUIT_COUNT: usize, const LEVEL_COUNT: usize>
    Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Returns the current round number.
    #[inline]
    pub fn round(&self) -> usize {
        self.round
    }

    /// Returns a shared reference to the participant data for `id` from the registry.
    #[inline]
    pub fn participant(&self, id: &C::Identifier) -> Option<&C::Participant> {
        self.registry.get(id)
    }

    /// Returns a mutable reference to the participant data for `id` from the registry.
    #[inline]
    pub fn participant_mut(&mut self, id: &C::Identifier) -> Option<&mut C::Participant> {
        self.registry.get_mut(id)
    }

    /// Returns the current position for a `participant` in the queue.
    #[inline]
    pub fn position(&self, participant: &C::Participant) -> Option<usize> {
        self.queue.position(participant.level(), participant.id())
    }

    /// Inserts `participant` into the queue.
    #[inline]
    pub fn insert_participant(&mut self, participant: &C::Participant) {
        self.queue
            .push_back_at(participant.level(), participant.id().clone());
    }
}
