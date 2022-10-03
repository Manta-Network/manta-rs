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

use crate::{
    ceremony::{
        participant::{Participant, Priority},
        registry::Registry,
        signature::{Nonce, SignedMessage},
    },
    groth16::{
        ceremony::{Ceremony, CeremonyError, Metadata, Queue, Round, UnexpectedError},
        mpc::{verify_transform, Proof, State},
    },
};
use core::mem;
use manta_util::{time::lock::Timed, BoxArray};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Ceremony Coordinator
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            serialize = r"
                R: Serialize,
                C::Challenge: Serialize,
                C::Participant: Serialize,
            ",
            deserialize = r"
                R: Deserialize<'de>,
                C::Challenge: Deserialize<'de>,
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
    challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,

    /// Latest Contributor
    ///
    /// This participant was the last one to perform a successful contribution to the ceremony.
    latest_contributor: Option<C::Participant>,

    /// Latest Proof
    latest_proof: Option<BoxArray<Proof<C>, CIRCUIT_COUNT>>,

    /// Ceremony Metadata
    metadata: Metadata,

    /// Current Round Number
    round: usize,

    /// Participant Queue
    #[cfg_attr(feature = "serde", serde(skip))]
    queue: Queue<C, LEVEL_COUNT>,

    /// Participant Lock
    #[cfg_attr(feature = "serde", serde(skip))]
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
        challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
        metadata: Metadata,
    ) -> Self {
        assert!(
            metadata.ceremony_size.matches(state.as_slice()),
            "Mismatch of metadata `{:?}` and state.",
            metadata,
        );
        Self {
            registry,
            state,
            challenge,
            latest_contributor: None,
            latest_proof: None,
            metadata,
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

    /// Returns the metadata for this ceremony.
    #[inline]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
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
    #[inline]
    pub fn queue_mut(&mut self) -> &mut Queue<C, LEVEL_COUNT> {
        &mut self.queue
    }

    /// Returns the current round state.
    #[inline]
    pub fn round_state(&self) -> Round<C>
    where
        C::Challenge: Clone,
    {
        Round::new(self.state.to_vec().into(), self.challenge.to_vec().into())
    }

    /// Preprocesses a request by checking the nonce and verifying the signature.
    #[inline]
    pub fn preprocess_request<T>(
        &mut self,
        request: &SignedMessage<C, C::Identifier, T>,
    ) -> Result<C::Priority, CeremonyError<C>>
    where
        T: Serialize,
    {
        let participant = self
            .registry
            .get_mut(request.identifier())
            .ok_or(CeremonyError::NotRegistered)?;
        if participant.has_contributed() {
            return Err(CeremonyError::AlreadyContributed);
        }
        let participant_nonce = participant.nonce();
        if !participant_nonce.is_valid() {
            return Err(CeremonyError::Unexpected(UnexpectedError::AllNoncesUsed));
        }
        request
            .verify(participant_nonce.clone(), participant.verifying_key())
            .map_err(|_| CeremonyError::InvalidSignature {
                expected_nonce: participant_nonce.clone(),
            })?;
        participant.increment_nonce();
        Ok(participant.priority())
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

    /// Updates the expired lock by reducing the priority of its participant and setting its
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

    /// Checks the lock for `participant`.
    #[inline]
    pub fn check_lock(&mut self, participant: &C::Identifier) -> Result<(), CeremonyError<C>> {
        if self
            .participant_lock
            .has_expired(self.metadata.contribution_time_limit)
        {
            Self::check_lock_update_errors(true, &self.update_expired_lock(), participant)
        } else {
            Self::check_lock_update_errors(false, self.participant_lock.get(), participant)
        }
    }

    /// Updates the MPC state and challenge using client's contribution. If the contribution is
    /// valid, the participant will be removed from the waiting queue, and cannot participate in
    /// this ceremony again.
    ///
    /// # Registration
    ///
    /// This method requires that `participant` is already registered.
    #[inline]
    pub fn update(
        &mut self,
        participant: &C::Identifier,
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        proof: BoxArray<Proof<C>, CIRCUIT_COUNT>,
    ) -> Result<(), CeremonyError<C>> {
        self.check_lock(participant)?;
        for (i, (state, proof)) in state.into_iter().zip(proof.clone().into_iter()).enumerate() {
            let next_challenge = C::challenge(&self.challenge[i], &self.state[i], &state, &proof);
            self.state[i] = verify_transform(&self.challenge[i], &self.state[i], state, proof)
                .map_err(|_| CeremonyError::BadRequest)?
                .1;
            self.challenge[i] = next_challenge;
        }
        self.latest_proof = Some(proof);
        self.participant_lock.set(self.queue.pop_front());
        match self.participant_mut(participant) {
            Some(participant) => participant.set_contributed(),
            _ => {
                return Err(CeremonyError::Unexpected(
                    UnexpectedError::MissingRegisteredParticipant,
                ));
            }
        };
        self.increment_round();
        Ok(())
    }
}
