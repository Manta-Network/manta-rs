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
        message::CeremonyError,
        queue::{HasIdentifier, Priority, Queue},
        registry::Registry,
        state::{MPCState, ServerSize},
    },
    mpc::Verify,
};
use core::{fmt::Debug, mem, time::Duration};
use manta_crypto::arkworks::serialize::{
    CanonicalDeserialize, CanonicalSerialize, SerializationError,
};
use manta_util::time::lock::Timed;
use std::io::{Read, Write};

/// Time limit for a participant at the front of the queue to contribute with unit as second
pub const TIME_LIMIT: Duration = Duration::from_secs(360);

/// Coordinator with `C` as CeremonyConfig, `N` as the number of priority levels, and `M` as the number of circuits
pub struct Coordinator<C, const N: usize, const M: usize>
where
    C: CeremonyConfig,
{
    /// Number of Contributions
    pub num_contributions: usize,

    /// Proof
    pub proof: Option<[Proof<C>; M]>,

    /// Latest Participant that Has Contributed
    pub latest_contributor: Option<C::Participant>,

    /// State
    pub state: [State<C>; M],

    /// Challenge
    pub challenge: [Challenge<C>; M],

    /// Registry of participants
    pub registry: Registry<ParticipantIdentifier<C>, C::Participant>,

    /// Queue of participants
    pub queue: Queue<C::Participant, N>,

    /// Participant Lock
    pub lock: Timed<Option<ParticipantIdentifier<C>>>,

    /// Size of state
    pub size: ServerSize,
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
        size: ServerSize,
    ) -> Self {
        Self {
            num_contributions,
            proof,
            latest_contributor,
            state,
            challenge,
            registry,
            size,
            queue: Queue::new(),
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
    fn update_expired_lock(&mut self) -> Option<ParticipantIdentifier<C>> {
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
    fn check_lock_update_errors(
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
        state: [State<C>; M],
        proof: [Proof<C>; M],
    ) -> Result<(), CeremonyError<C>> {
        if self.lock.has_expired(TIME_LIMIT) {
            Self::check_lock_update_errors(true, &self.update_expired_lock(), participant)?;
        } else {
            Self::check_lock_update_errors(false, self.lock.get(), participant)?;
        }
        for (i, (state, proof)) in state.into_iter().zip(proof.iter()).enumerate() {
            self.state[i] =
                C::Setup::verify_transform(&self.challenge[i], &self.state[i], state, proof)
                    .map_err(|_| CeremonyError::BadRequest)?
                    .1;
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

    /// Pops the current contributor and returns the participant identifier that is skipped.
    #[inline]
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

impl<C, const N: usize, const M: usize> CanonicalSerialize for Coordinator<C, N, M>
where
    C: CeremonyConfig,
    Proof<C>: CanonicalSerialize,
    State<C>: CanonicalSerialize,
    Challenge<C>: CanonicalSerialize,
    ParticipantIdentifier<C>: CanonicalSerialize,
    C::Participant: CanonicalSerialize,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        self.num_contributions
            .serialize(&mut writer)
            .expect("Serialize should succeed");
        self.proof
            .as_ref()
            .expect("Proof should exit.")
            .serialize(&mut writer)
            .expect("Serialize should succeed");
        self.latest_contributor
            .serialize(&mut writer)
            .expect("Serialize should succeed");
        self.state
            .serialize(&mut writer)
            .expect("Serialize should succeed");
        self.challenge
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        self.registry
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        self.size
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.num_contributions.serialized_size()
            + self
                .proof
                .as_ref()
                .expect("Proof should exit.")
                .serialized_size()
            + self.latest_contributor.serialized_size()
            + self.state.serialized_size()
            + self.challenge.serialized_size()
            + self.registry.serialized_size()
            + self.size.serialized_size()
    }
}

impl<C, const N: usize, const M: usize> CanonicalDeserialize for Coordinator<C, N, M>
where
    C: CeremonyConfig,
    Proof<C>: CanonicalDeserialize + Debug,
    State<C>: CanonicalDeserialize + Debug,
    Challenge<C>: CanonicalDeserialize + Debug,
    ParticipantIdentifier<C>: CanonicalDeserialize,
    C::Participant: CanonicalDeserialize,
{
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let num_contributions =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserializing should succeed.");
        let mut proofs = Vec::new();
        for _ in 0..M {
            let proof: Proof<C> = CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing should succeed.");
            proofs.push(proof);
        }
        let latest_contributor: C::Participant =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserializing should succeed.");
        let mut states = Vec::new();
        for _ in 0..M {
            let state: State<C> = CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing should succeed.");
            states.push(state);
        }
        let mut challenges = Vec::new();
        for _ in 0..M {
            let challenge: Challenge<C> = CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing should succeed.");
            challenges.push(challenge);
        }
        Ok(Self {
            num_contributions,
            proof: Some(
                proofs
                    .try_into()
                    .expect("Converting to fixed-size array should succeed."),
            ),
            latest_contributor: Some(latest_contributor),
            state: states
                .try_into()
                .expect("Converting to fixed-size array should succeed."),
            challenge: challenges
                .try_into()
                .expect("Converting to fixed-size array should succeed."),
            registry: CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing should succeed."),
            queue: Queue::<C::Participant, N>::new(),
            size: CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing should succeed."),
            lock: Timed::default(),
        })
    }
}
