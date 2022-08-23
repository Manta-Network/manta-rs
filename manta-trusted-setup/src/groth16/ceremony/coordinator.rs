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
        ceremony::{Ceremony, Participant},
        mpc::StateSize,
    },
    mpc::{Challenge, Proof, State},
};
use manta_util::{collections::vec_deque::MultiVecDeque, Array, BoxArray};

///
pub trait Registry<K, V> {
    ///
    fn register(&mut self, key: K, value: V) -> bool;

    ///
    fn get(&self, key: &K) -> Option<&V>;

    ///
    fn get_mut(&mut self, key: &K) -> Option<&mut V>;

    ///
    fn has_contributed(&self, key: &K) -> bool;
}

///
pub type ProofArray<C, const N: usize> = BoxArray<Proof<C>, N>;

///
pub type StateArray<C, const N: usize> = BoxArray<State<C>, N>;

///
pub type ChallengeArray<C, const N: usize> = BoxArray<Challenge<C>, N>;

///
pub type Queue<C, const LEVEL_COUNT: usize> =
    MultiVecDeque<<C as Ceremony>::Identifier, LEVEL_COUNT>;

///
pub struct Coordinator<C, R, const CIRCUIT_COUNT: usize, const LEVEL_COUNT: usize>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    ///
    registry: R,

    ///
    queue: Queue<C, LEVEL_COUNT>,

    /// State
    state: StateArray<C, CIRCUIT_COUNT>,

    /// Challenge
    challenge: ChallengeArray<C, CIRCUIT_COUNT>,

    ///
    latest_contributor: Option<C::Participant>,

    /// Latest Proof
    latest_proof: Option<ProofArray<C, CIRCUIT_COUNT>>,

    /// Current Round Number
    round: usize,

    ///
    size: Array<StateSize, CIRCUIT_COUNT>,
}

impl<C, R, const CIRCUIT_COUNT: usize, const LEVEL_COUNT: usize>
    Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    ///
    #[inline]
    pub fn round(&self) -> usize {
        self.round
    }

    ///
    #[inline]
    pub fn participant(&self, id: &C::Identifier) -> Option<&C::Participant> {
        self.registry.get(id)
    }

    ///
    #[inline]
    pub fn participant_mut(&mut self, id: &C::Identifier) -> Option<&mut C::Participant> {
        self.registry.get_mut(id)
    }

    ///
    #[inline]
    pub fn is_waiting(&self, id: &C::Identifier) -> Option<bool> {
        self.participant(id).map(|p| self.position(p).is_some())
    }

    ///
    #[inline]
    pub fn is_next(&self, participant: &C::Participant) -> bool {
        self.queue.is_front(participant.id())
    }

    ///
    #[inline]
    pub fn position(&self, participant: &C::Participant) -> Option<usize> {
        self.queue.position(participant.level(), participant.id())
    }

    ///
    #[inline]
    pub fn insert_participant(&mut self, participant: &C::Participant) {
        self.queue
            .push_back_at(participant.level(), participant.id().clone());
    }

    ///
    #[inline]
    pub fn skip_current_contributor(&mut self) -> Option<C::Identifier> {
        self.queue.pop_front()
    }
}
