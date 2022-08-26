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
        message::{CeremonyError, MPCState, ServerSize},
        participant::{HasIdentifier, Priority},
        queue::Queue,
        registry::Registry,
    },
    mpc::Verify,
    util::AsBytes,
};
use core::{mem, time::Duration};
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_util::{
    serde::{Deserialize, Serialize},
    time::lock::Timed,
    Array,
};

/// Time limit for a participant at the front of the queue to contribute with unit as second
pub const TIME_LIMIT: Duration = Duration::from_secs(360);

/// Coordinator with `C` as CeremonyConfig, `N` as the number of priority levels, and `M` as the number of circuits
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = "
            Proof<C>: CanonicalSerialize,
            C::Participant: Serialize, 
            State<C>: CanonicalSerialize, 
            Challenge<C>: CanonicalSerialize,
            ParticipantIdentifier<C>: Serialize,
        ",
        deserialize = "
            Proof<C>: CanonicalDeserialize,
            C::Participant: Deserialize<'de>, 
            State<C>: CanonicalDeserialize, 
            Challenge<C>: CanonicalDeserialize,
            ParticipantIdentifier<C>: Deserialize<'de>,
        ",
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Coordinator<C, const N: usize, const M: usize>
where
    C: CeremonyConfig,
{
    /// Number of Contributions
    pub num_contributions: usize,

    /// Proof
    pub proof: Option<Array<AsBytes<Proof<C>>, M>>,

    /// Latest Participant that Has Contributed
    pub latest_contributor: Option<C::Participant>,

    /// State
    pub state: Array<AsBytes<State<C>>, M>,

    /// Challenge
    pub challenge: Array<AsBytes<Challenge<C>>, M>,

    /// Registry of participants
    pub registry: Registry<ParticipantIdentifier<C>, C::Participant>,

    /// Queue of participants
    #[serde(skip)]
    pub queue: Queue<C::Participant, N>,

    /// Participant Lock
    #[serde(skip)]
    pub lock: Timed<Option<ParticipantIdentifier<C>>>,

    /// Size of state
    pub size: ServerSize<M>,
}

impl<C, const N: usize, const M: usize> Coordinator<C, N, M>
where
    C: CeremonyConfig,
{
    /// Initializes a coordinator with the initial state and challenge.
    #[inline]
    pub fn new(
        num_contributions: usize,
        proof: Option<Array<AsBytes<Proof<C>>, M>>,
        latest_contributor: Option<C::Participant>,
        state: Array<AsBytes<State<C>>, M>,
        challenge: Array<AsBytes<Challenge<C>>, M>,
        registry: Registry<ParticipantIdentifier<C>, C::Participant>,
        size: ServerSize<M>,
    ) -> Self {
        Self {
            num_contributions,
            proof,
            latest_contributor,
            state,
            challenge,
            registry,
            size,
            queue: Queue::default(),
            lock: Timed::default(),
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

    /// Updates the expired lock by reducing the priority of it's participant and setting it's
    /// contained value to the new front of the queue. The previous participant in the lock is
    /// returned.
    #[inline]
    pub fn update_expired_lock(&mut self) -> Option<ParticipantIdentifier<C>> {
        self.lock.mutate(|p| {
            if let Some(identifier) = p {
                if let Some(participant) = self.registry.get_mut(identifier) {
                    participant.reduce_priority();
                }
            }
            mem::replace(p, self.queue.pop())
        })
    }

    /// Checks the lock update errors for the [`Coordinator::update`] method.
    #[inline]
    pub fn check_lock_update_errors(
        has_expired: bool,
        lhs: &Option<ParticipantIdentifier<C>>,
        rhs: &ParticipantIdentifier<C>,
    ) -> Result<(), CeremonyError<C>> {
        match lhs {
            Some(lhs) if lhs == rhs && has_expired => Err(CeremonyError::Timeout),
            Some(lhs) if lhs != rhs => Err(CeremonyError::NotYourTurn),
            _ => Ok(()),
        }
    }

    /// Updates the MPC state and challenge using client's contribution. If the contribution is
    /// valid, the participant will be removed from the waiting queue, and cannot participate in
    /// this ceremony again.
    #[inline]
    pub fn update(
        &mut self,
        participant: &ParticipantIdentifier<C>,
        state: Array<AsBytes<State<C>>, M>,
        proof: Array<AsBytes<Proof<C>>, M>,
    ) -> Result<(), CeremonyError<C>>
    where
        Challenge<C>: CanonicalDeserialize,
        State<C>: CanonicalDeserialize + CanonicalSerialize,
        Proof<C>: CanonicalDeserialize,
    {
        if self.lock.has_expired(TIME_LIMIT) {
            Self::check_lock_update_errors(true, &self.update_expired_lock(), participant)?;
        } else {
            Self::check_lock_update_errors(false, self.lock.get(), participant)?;
        }
        for (i, (state, proof)) in state.into_iter().zip(proof.iter()).enumerate() {
            self.state[i] = AsBytes::from_actual(
                C::Setup::verify_transform(
                    &self.challenge[i]
                        .to_actual()
                        .expect("To actual should succeed."),
                    &self.state[i]
                        .to_actual()
                        .expect("To actual should succeed."),
                    state.to_actual().expect("To actual should succeed."),
                    &proof.to_actual().expect("To actual should succeed."),
                )
                .map_err(|_| CeremonyError::BadRequest)?
                .1,
            );
        }
        self.proof = Some(proof);
        self.lock.set(self.queue.pop());
        Ok(())
    }

    /// Enqueues a participant into the queue on the server if the participant has registered and
    /// has not contributed.
    #[inline]
    pub fn enqueue_participant(
        &mut self,
        participant_id: &ParticipantIdentifier<C>,
    ) -> Result<(), CeremonyError<C>> {
        // TODO: Enqueue successfully should return a succeed message and an updated nonce.
        let participant = self.registry.get(participant_id);
        match participant {
            Some(participant) => {
                if self.queue.position(participant).is_none() {
                    if self.registry.has_contributed(&participant.identifier()) {
                        return Err(CeremonyError::BadRequest); // TODO: You have contributed.
                    }
                    self.queue.push(participant);
                    if self.lock.has_expired(TIME_LIMIT) {
                        self.update_expired_lock();
                    }
                    Ok(())
                } else {
                    Err(CeremonyError::BadRequest) // TODO: You are already in queue.
                }
            }
            _ => Err(CeremonyError::NotRegistered), // TODO: You have not registered.
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
            Some(participant) => Ok(self.queue.position(participant).is_some()),
            _ => Err(CeremonyError::NotRegistered), // TODO: You have not registered.
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

    /// Get number of contributions
    #[inline]
    pub fn num_contributions(&self) -> usize {
        self.num_contributions
    }
}
