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
use core::{fmt::Debug, mem};
use manta_util::{time::lock::Timed, BoxArray};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Queue and Participant Lock
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = "C::Identifier: Debug"),
    Default(bound = ""),
    Eq(bound = ""),
    PartialEq(bound = "")
)]
pub struct LockQueue<C, const LEVEL_COUNT: usize>
where
    C: Ceremony,
{
    /// Participant Queue
    queue: Queue<C, LEVEL_COUNT>,

    /// Participant Lock
    participant_lock: Timed<Option<C::Identifier>>,
}

impl<C, const LEVEL_COUNT: usize> LockQueue<C, LEVEL_COUNT>
where
    C: Ceremony,
{
    /// Returns a mutable reference to `queue`.
    #[inline]
    pub fn queue_mut(&mut self) -> &mut Queue<C, LEVEL_COUNT> {
        &mut self.queue
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
    pub fn update_expired_lock<R>(&mut self, registry: &mut R) -> Option<C::Identifier>
    where
        R: Registry<C::Identifier, C::Participant>,
    {
        self.participant_lock.mutate(|p| {
            if let Some(identifier) = p {
                if let Some(participant) = registry.get_mut(identifier) {
                    participant.reduce_priority();
                }
            }
            mem::replace(p, self.queue.pop_front())
        })
    }

    /// Checks the lock for `participant`.
    #[inline]
    pub fn check_lock<R>(
        &mut self,
        participant: &C::Identifier,
        registry: &mut R,
        metadata: &Metadata,
    ) -> Result<(), CeremonyError<C>>
    where
        R: Registry<C::Identifier, C::Participant>,
    {
        if self
            .participant_lock
            .has_expired(metadata.contribution_time_limit)
        {
            Self::check_lock_update_errors(true, &self.update_expired_lock(registry), participant)
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
    pub fn update<R>(
        &mut self,
        participant: &C::Identifier,
        registry: &mut R,
        metadata: &Metadata,
    ) -> Result<(), CeremonyError<C>>
    where
        R: Registry<C::Identifier, C::Participant>,
    {
        self.check_lock(participant, registry, metadata)?;
        self.participant_lock.set(self.queue.pop_front());
        match participant_mut::<C, R>(registry, participant) {
            Some(participant) => participant.set_contributed(),
            _ => {
                return Err(CeremonyError::Unexpected(
                    UnexpectedError::MissingRegisteredParticipant,
                ));
            }
        };
        Ok(())
    }
}

/// State, Challenge and Latest Proof
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            serialize = r"
                C::Challenge: Serialize,
                C::Participant: Serialize,
            ",
            deserialize = r"
                C::Challenge: Deserialize<'de>,
                C::Participant: Deserialize<'de>,
            "
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(Clone)]
pub struct StateChallengeProof<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// State
    state: BoxArray<State<C>, CIRCUIT_COUNT>,

    /// Challenge
    challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,

    /// Latest Proof
    latest_proof: Option<BoxArray<Proof<C>, CIRCUIT_COUNT>>,

    /// Round
    round: u64,
}

impl<C, const CIRCUIT_COUNT: usize> StateChallengeProof<C, CIRCUIT_COUNT>
where
    C: Ceremony,
{
    /// Builds a new [`StateChallengeProof`] from `state` and `challenge`.
    #[inline]
    pub fn new(
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
    ) -> Self {
        Self {
            state,
            challenge,
            latest_proof: None,
            round: 0,
        }
    }

    /// Returns the current round number.
    #[inline]
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Increments the round number.
    #[inline]
    pub fn increment_round(&mut self) {
        self.round += 1;
    }

    /// Returns the current round state.
    #[inline]
    pub fn round_state(&self) -> Round<C>
    where
        C::Challenge: Clone,
    {
        Round::new(self.state.to_vec().into(), self.challenge.to_vec().into())
    }

    /// Returns the challenge.
    #[inline]
    pub fn challenge(&self) -> &BoxArray<C::Challenge, CIRCUIT_COUNT> {
        &self.challenge
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
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        proof: BoxArray<Proof<C>, CIRCUIT_COUNT>,
    ) -> Result<u64, CeremonyError<C>> {
        for (i, (state, proof)) in state.into_iter().zip(proof.clone().into_iter()).enumerate() {
            let next_challenge = C::challenge(&self.challenge[i], &self.state[i], &state, &proof);
            self.state[i] = verify_transform(&self.challenge[i], &self.state[i], state, proof)
                .map_err(|_| CeremonyError::BadRequest)?
                .1;
            self.challenge[i] = next_challenge;
        }
        self.latest_proof = Some(proof);
        self.increment_round();
        Ok(self.round())
    }
}

/// Preprocesses a request by checking the nonce and verifying the signature.
#[inline]
pub fn preprocess_request<C, R, T>(
    registry: &mut R,
    request: &SignedMessage<C, C::Identifier, T>,
) -> Result<C::Priority, CeremonyError<C>>
where
    T: Serialize,
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    let participant = registry
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

/// Returns a shared reference to the participant data for `id` from the registry.
#[inline]
pub fn participant<'a, C, R>(registry: &'a R, id: &'a C::Identifier) -> Option<&'a C::Participant>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    registry.get(id)
}

/// Returns a mutable reference to the participant data for `id` from the registry.
#[inline]
pub fn participant_mut<'a, C, R>(
    registry: &'a mut R,
    id: &'a C::Identifier,
) -> Option<&'a mut C::Participant>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    registry.get_mut(id)
}
