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
        config::{CeremonyConfig, Challenge, ParticipantIdentifier, Proof, State},
        queue::{HasIdentifier, Queue},
        registry::Registry,
        util::MPCState,
        CeremonyError,
    },
    mpc::Verify,
};

/// Coordinator with `C` as CeremonyConfig, `N` as the number of priority levels, and `M` as the number of circuits
pub struct Coordinator<C, const N: usize, const M: usize>
where
    C: CeremonyConfig,
{
    /// Number of Contributions
    pub(crate) num_contributions: usize,

    /// Proof
    pub(crate) proof: Option<[Proof<C>; M]>,

    /// Latest Participant that Has Contributed
    pub(crate) latest_contributor: Option<C::Participant>,

    /// State
    pub(crate) state: [State<C>; M],

    /// Challenge
    pub(crate) challenge: [Challenge<C>; M],

    /// Registry of participants
    pub(crate) registry: Registry<ParticipantIdentifier<C>, C::Participant>,

    /// Queue of participants
    pub(crate) queue: Queue<C::Participant, N>,
}

impl<C, const N: usize, const M: usize> Coordinator<C, N, M>
where
    C: CeremonyConfig,
{
    /// Initializes a coordinator with the initial state and challenge.
    #[inline]
    pub fn new(
        num_contributions: usize,
        proof: Option<[Proof<C>; M]>,
        latest_contributor: Option<C::Participant>,
        state: [State<C>; M],
        challenge: [Challenge<C>; M],
        registry: Registry<ParticipantIdentifier<C>, C::Participant>,
    ) -> Self {
        Self {
            num_contributions,
            proof,
            latest_contributor,
            state,
            challenge,
            registry,
            queue: Queue::new(),
        }
    }

    /// Gets the current state and challenge.
    #[inline]
    pub fn state_and_challenge(&self) -> MPCState<C, M>
    where
        State<C>: Clone,
        Challenge<C>: Clone,
    {
        MPCState {
            state: self.state.clone(),
            challenge: self.challenge.clone(),
        }
    }

    /// Checks if the `participant` is the next.
    #[inline]
    pub fn is_next(&self, participant: &ParticipantIdentifier<C>) -> bool {
        self.queue.is_at_front(participant)
    }

    /// Gets the position of `participant` and returns `None` if `participant`
    /// is not in the queue.
    #[inline]
    pub fn position(&self, participant: &C::Participant) -> Option<usize> {
        self.queue.position(participant)
    }

    /// Updates the MPC state and challenge using client's contribution. If the contribution is valid,
    /// the participant will be removed from the waiting queue, and cannot participate in this ceremony
    /// again.
    #[inline]
    pub fn update(
        &mut self,
        participant: &ParticipantIdentifier<C>,
        state: [State<C>; M],
        proof: [Proof<C>; M],
    ) -> Result<(), CeremonyError<C>> {
        if !self.queue.is_at_front(participant) {
            return Err(CeremonyError::<C>::BadRequest); // TODO: Why use BadRequest instead of NotYourTurn?
        };
        for i in 0..M {
            take_mut::take(&mut self.state[i], |self_state| {
                C::Setup::verify_transform(
                    &self.challenge[i],
                    self_state,
                    state[i].clone(),
                    proof[i].clone(),
                )
                .expect("Verify transform on received contribution should succeed.")
                .1
            });
        }
        self.proof = Some(proof);
        self.queue
            .pop()
            .expect("One participant should have just contributed.");
        Ok(())
    }

    /// Enqueues a participant into the queue on the server if the participant has registered and has not contributed.
    #[inline]
    pub fn enqueue_participant(
        &mut self,
        participant_id: &ParticipantIdentifier<C>,
    ) -> Result<(), CeremonyError<C>> {
        // TODO: Enqueue successfully should return a succeed message and an updated nonce.
        let participant = self.registry.get(participant_id);
        match participant {
            Some(participant) => {
                if matches!(self.queue.position(participant), None) {
                    if self.registry.has_contributed(&participant.identifier()) {
                        return Err(CeremonyError::BadRequest); // TODO: You have contributed.
                    }
                    self.queue.push(participant);
                    Ok(())
                } else {
                    Err(CeremonyError::BadRequest) // TODO: You are already in queue.
                }
            }
            None => Err(CeremonyError::NotRegistered), // TODO: You have not registered.
        }
    }

    /// Checks if the participant is in queue. Returning `CeremonyError::NotRegistered`
    /// if the `participant_id` is not in the registry.
    #[inline]
    pub fn is_in_queue(
        &self,
        participant_id: &ParticipantIdentifier<C>,
    ) -> Result<bool, CeremonyError<C>> {
        match self.registry.get(participant_id) {
            Some(participant) => Ok(!matches!(self.queue.position(participant), None)),
            None => Err(CeremonyError::NotRegistered), // TODO: You have not registered.
        }
    }

    /// Gets the participant with the given identifier and returns `None` if not found.
    #[inline]
    pub fn get_participant(
        &self,
        identifier: &ParticipantIdentifier<C>,
    ) -> Option<&C::Participant> {
        self.registry.get(identifier)
    }

    /// Gets the mutable reference of participant with the given identifier and returns `None` if not found.
    #[inline]
    pub fn get_participant_mut(
        &mut self,
        identifier: &ParticipantIdentifier<C>,
    ) -> Option<&mut C::Participant> {
        self.registry.get_mut(identifier)
    }

    /// Pops the current contributor and returns the participant identifier that is skipped.
    pub fn skip_current_contributor(
        // TODO: When should we use that?
        &mut self,
    ) -> Result<ParticipantIdentifier<C>, CeremonyError<C>> {
        self.queue.pop().ok_or(CeremonyError::BadRequest)
    }

    /// Get number of contributions
    #[inline]
    pub fn num_contributions(&self) -> usize {
        self.num_contributions
    }
}
