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

//! Coordinator

use crate::groth16::{
    ceremony::{
        message::{MPCState, Signed},
        registry::Registry,
        signature::{check_nonce, verify},
        Ceremony, CeremonyError, Challenge, Participant, Queue, UserPriority,
    },
    mpc::{verify_transform, Proof, State, StateSize},
};
use core::{mem, time::Duration};
use manta_util::{time::lock::Timed, BoxArray};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Time limit for a participant at the front of the queue to contribute with unit as second
pub const TIME_LIMIT: Duration = Duration::from_secs(360);

/// Ceremony Coordinator
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            serialize = r"
                R: Serialize,
                Challenge<C>: Serialize,
                C::Participant: Serialize,
            ",
            deserialize = r"
                R: Deserialize<'de>,
                Challenge<C>: Deserialize<'de>,
                C::Participant: Deserialize<'de>,
            "
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
pub struct Coordinator<C, R, const CIRCUIT_COUNT: usize, const LEVEL_COUNT: usize>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Participant Registry
    registry: R,

    /// State
    state: BoxArray<State<C>, CIRCUIT_COUNT>,

    /// Challenge
    challenge: BoxArray<Challenge<C>, CIRCUIT_COUNT>,

    /// Latest Contributor
    ///
    /// This participant was the last one to perform a successful contribution to the ceremony.
    latest_contributor: Option<C::Participant>,

    /// Latest Proof
    latest_proof: Option<BoxArray<Proof<C>, CIRCUIT_COUNT>>,

    /// State Sizes
    size: BoxArray<StateSize, CIRCUIT_COUNT>,

    /// Current Round Number
    round: usize,

    /// Participant Queue
    #[serde(skip)]
    queue: Queue<C, LEVEL_COUNT>,

    /// Participant Lock
    #[serde(skip)]
    participant_lock: Timed<Option<C::Identifier>>,
}

impl<C, R, const CIRCUIT_COUNT: usize, const LEVEL_COUNT: usize>
    Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Builds a new [`Coordinator`].
    #[inline]
    pub fn new(
        registry: R,
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        challenge: BoxArray<Challenge<C>, CIRCUIT_COUNT>,
        size: BoxArray<StateSize, CIRCUIT_COUNT>,
    ) -> Self {
        Self {
            registry,
            state,
            challenge,
            latest_contributor: None,
            latest_proof: None,
            size,
            round: 0,
            queue: Default::default(),
            participant_lock: Default::default(),
        }
    }

    /// Returns the current round number.
    #[inline]
    pub fn round(&self) -> usize {
        self.round
    }

    /// Increments the round number.
    #[inline]
    pub fn increment_round(&mut self) {
        self.round += 1;
    }

    /// Returns the state size.
    #[inline]
    pub fn size(&self) -> &[StateSize; CIRCUIT_COUNT] {
        &self.size
    }

    /// Returns the registry.
    #[inline]
    pub fn registry(&self) -> &R {
        &self.registry
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

    /// Returns a mutable reference to `queue`.
    pub fn queue_mut(&mut self) -> &mut Queue<C, LEVEL_COUNT> {
        &mut self.queue
    }

    /// Gets the current state and challenge.
    #[inline]
    pub fn state_and_challenge(&self) -> MPCState<C, CIRCUIT_COUNT>
    where
        Challenge<C>: Clone,
    {
        MPCState {
            state: self.state.clone(),
            challenge: self.challenge.clone(),
        }
    }

    /// Preprocesses a request by checking nonce and verifying signature.
    #[inline]
    pub fn preprocess_request<T>(
        &mut self,
        request: &Signed<T, C>,
    ) -> Result<UserPriority, CeremonyError<C>>
    where
        T: Serialize,
    {
        let participant = self
            .registry
            .get_mut(&request.identifier)
            .ok_or_else(|| CeremonyError::NotRegistered)?;
        if participant.has_contributed() {
            return Err(CeremonyError::AlreadyContributed);
        }
        let participant_nonce = participant.get_nonce();
        if !check_nonce(&participant_nonce, &request.nonce) {
            return Err(CeremonyError::NonceNotInSync(participant_nonce));
        };
        verify::<T, C>(
            participant.verifying_key(),
            participant_nonce,
            &request.message,
            &request.signature,
        )
        .map_err(|_| CeremonyError::BadRequest)?;
        participant.increment_nonce();
        Ok(participant.level())
    }

    /// Checks the lock update errors for the [`Coordinator::update`] method.
    #[inline]
    pub fn check_lock_update_errors(
        has_expired: bool,
        lhs: &Option<C::Identifier>,
        rhs: &C::Identifier,
    ) -> Result<(), CeremonyError<C>> {
        match lhs {
            Some(lhs) if lhs == rhs && has_expired => Err(CeremonyError::Timeout),
            Some(lhs) if lhs != rhs => Err(CeremonyError::NotYourTurn),
            _ => Ok(()),
        }
    }

    /// Updates the expired lock by reducing the priority of it's participant and setting it's
    /// contained value to the new front of the queue. The previous participant in the lock is
    /// returned.
    #[inline]
    pub fn update_expired_lock(&mut self) -> Option<C::Identifier> {
        self.participant_lock.mutate(|p| {
            if let Some(identifier) = p {
                if let Some(participant) = self.registry.get_mut(identifier) {
                    participant.reduce_priority();
                }
            }
            mem::replace(p, self.queue.pop_front())
        })
    }

    /// Checks lock for `participant`.
    #[inline]
    pub fn check_lock(&mut self, participant: &C::Identifier) -> Result<(), CeremonyError<C>> {
        if self.participant_lock.has_expired(TIME_LIMIT) {
            Self::check_lock_update_errors(true, &self.update_expired_lock(), participant)
        } else {
            Self::check_lock_update_errors(false, self.participant_lock.get(), participant)
        }
    }

    /// Updates the MPC state and challenge using client's contribution. If the contribution is
    /// valid, the participant will be removed from the waiting queue, and cannot participate in
    /// this ceremony again.
    #[inline]
    pub fn update(
        &mut self,
        participant: &C::Identifier,
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        proof: BoxArray<Proof<C>, CIRCUIT_COUNT>,
    ) -> Result<(), CeremonyError<C>> {
        self.check_lock(participant)?;
        for (i, (state, proof)) in state.into_iter().zip(proof.clone().into_iter()).enumerate() {
            self.state[i] = verify_transform(&self.challenge[i], &self.state[i], state, proof)
                .map_err(|_| CeremonyError::BadRequest)?
                .1
        }
        self.latest_proof = Some(proof);
        self.participant_lock.set(self.queue.pop_front());
        match self.participant_mut(participant) {
            Some(participant) => participant.set_contributed(),
            None => return Err(CeremonyError::Unexpected),
        };
        self.increment_round();
        Ok(())
    }
}
