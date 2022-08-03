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

//! Ceremony Coordinator

use crate::{
    ceremony::{
        queue::{Identifier, Priority, Queue},
        registry::{Map, Registry},
        CeremonyError,
    },
    mpc,
};
use core::mem::take;

/// Coordinator with `V` as trusted setup verifier, `P` as participant, `M` as the map used by registry, `N` as the number of priority levels
pub struct Coordinator<V, P, M, const N: usize>
where
    V: mpc::Verify,
    P: Priority + Identifier,
    M: Map<Key = P::Identifier, Value = P>,
{
    /// States
    state: V::State,

    /// Challenge
    challenge: V::Challenge,

    /// Registry of participants
    registry: Registry<M>,

    /// Queue of participants
    queue: Queue<P, N>,
}

impl<V, P, M, const N: usize> Coordinator<V, P, M, N>
where
    V: mpc::Verify,
    P: Priority + Identifier,
    M: Map<Key = P::Identifier, Value = P>,
{
    /// Initializes a coordinator with the initial state and challenge.
    #[inline]
    pub fn new(state: V::State, challenge: V::Challenge) -> Self {
        Self {
            state,
            challenge,
            registry: Registry::default(),
            queue: Queue::new(),
        }
    }

    /// Gets the current state and challenge.
    #[inline]
    pub fn state_and_challenge(&self) -> (&V::State, &V::Challenge) {
        (&self.state, &self.challenge)
    }

    /// Checks if the `participant` is the next.
    #[inline]
    pub fn is_next(&self, participant: &P) -> bool {
        self.queue.is_at_front(participant)
    }

    /// Gets the position of `participant` and returns `None` if `participant`
    /// is not in the queue.
    #[inline]
    pub fn position(&self, participant: &P) -> Option<usize> {
        self.queue.position(participant)
    }

    /// Updates the MPC state and challenge using client's contribution. If the contribution is valid,
    /// the participant will be removed from the waiting queue, and cannot participate in this ceremony
    /// again.
    #[inline]
    pub fn update(
        &mut self,
        participant: &P::Identifier,
        state: V::State,
        proof: V::Proof,
    ) -> Result<(), CeremonyError>
    where
        V::State: Default, // TODO: we can use `take_mut` crate to avoid this, but need to think more
    {
        let participant = self
            .registry
            .get(participant)
            .ok_or(CeremonyError::NotRegistered)
            .expect("Get the participant from registry should succeed.");
        if !self.queue.is_at_front(participant) {
            return Err(CeremonyError::NotYourTurn);
        };
        (_, self.state) = V::verify_transform(&self.challenge, take(&mut self.state), state, proof)
            .expect("Verify transform on received contribution should succeed.");
        self.queue.pop();
        Ok(())
    }

    /// Registers a participant and puts into the waiting queue.
    #[inline]
    pub fn register(&mut self, participant: P) -> Result<(), CeremonyError> {
        let participant = self
            .registry
            .register(participant.identifier(), participant)
            .expect("Register a participant should succeed.");
        self.queue
            .push(participant.priority(), participant.identifier());
        Ok(())
    }

    /// Gets the participant with the given identifier and returns `None` if not found.
    #[inline]
    pub fn get_participant(&self, identifier: &P::Identifier) -> Option<&P> {
        self.registry.get(identifier)
    }

    /// Pops the current contributor and moves to the back.
    #[inline]
    pub fn skip_current_contributor(&mut self) -> Result<(), CeremonyError> {
        let (priority, identifier) = self
            .queue
            .pop()
            .ok_or(CeremonyError::WaitingQueueEmpty)
            .expect("Poping the current participant should succeed.");
        self.queue.push(priority, identifier);
        Ok(())
    }
}
