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
//! Ceremony coordinator.

use crate::{
    ceremony::{
        queue::{Identifier, Priority, Queue},
        registry::{Map, Registry},
        signature,
        signature::{SignatureScheme, Verify as _},
        CeremonyError,
    },
    mpc,
};
use core::marker::PhantomData;

#[derive(derivative::Derivative)]
#[derivative(Clone(
    bound = "P::Identifier: Clone, V::State: Clone, V::Challenge: Clone, M: Clone, V: Clone"
))]
/// Coordinator with `V` as trusted setup verifier, `P` as participant, `M` as the map used by registry, `N` as the number of priority levels.
pub struct Coordinator<V, P, M, S, const N: usize>
where
    V: mpc::Verify,
    P: Priority + Identifier + signature::HasPublicKey,
    S: SignatureScheme,
    M: Map<Key = P::Identifier, Value = P>,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    state: V::State,
    challenge: V::Challenge,
    registry: Registry<M>,
    queue: Queue<P, N>,
    mpc_verifier: V,
    __: PhantomData<S>,
}

impl<V, P, M, S, const N: usize> Coordinator<V, P, M, S, N>
where
    V: mpc::Verify,
    P: Priority + Identifier + signature::HasPublicKey,
    S: SignatureScheme<PublicKey = P::PublicKey>,
    M: Map<Key = P::Identifier, Value = P>,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    /// Initialize the coordinator with the initial state and challenge.
    pub fn new(
        // add internal state
        mpc_verifier: V,
        state: V::State,
        challenge: V::Challenge,
    ) -> Self {
        Self {
            state,
            challenge,
            registry: Registry::default(),
            queue: Queue::default(),
            mpc_verifier,
            __: PhantomData,
        }
    }

    /// Get current state and challenge.
    pub fn state_and_challenge(&self) -> (&V::State, &V::Challenge) {
        (&self.state, &self.challenge)
    }

    /// Update the MPC state and challenge using client's contribution.
    /// If the contribution is valid, the participant will be removed from the waiting queue, and cannot
    /// participate in this ceremony again.
    pub fn update(
        &mut self,
        participant: &P::Identifier,
        transformed_state: V::State,
        proof: V::Proof,
        signature: &S::Signature,
    ) -> Result<(), CeremonyError>
    where
        V::State: Default, // we need this because `verify_transform` takes ownership of `self.state`
    {
        // get participant
        let participant = self
            .registry
            .get(participant)
            .ok_or(CeremonyError::NotRegistered)?;
        // make sure the message is from the participant
        let participant_public_key = participant.public_key();
        transformed_state.verify_integrity(&participant_public_key, signature)?;
        proof.verify_integrity(&participant_public_key, &signature)?;
        // make sure it is participant's turn
        if !self.queue.is_front(participant) {
            return Err(CeremonyError::NotYourTurn);
        };

        // verify and update the state and challenge
        let next_challenge = self.mpc_verifier.challenge(&self.state, &self.challenge);
        let transformed_state = self
            .mpc_verifier
            .verify_transform(
                core::mem::take(&mut self.state),
                transformed_state,
                next_challenge,
                proof,
            )
            .map_err(|_| CeremonyError::TrustedSetupError)?; // TODO: add more error description
        self.state = transformed_state;

        // remove the participant from the queue but the participant
        // will noe be removed from the registry, so the participant will not
        // be able to participate in this ceremony again.
        self.queue.pop();
        Ok(())
    }

    /// Register a participant and put them into the waiting queue.
    pub fn register(&mut self, participant: P) -> Result<(), CeremonyError> {
        let participant = self
            .registry
            .try_register(participant.identifier(), participant)?;
        self.queue.push(participant);
        Ok(())
    }

    /// Get the participant with the given identifier. Returns `None` if not found.
    pub fn get_participant(&self, identifier: &P::Identifier) -> Option<&P> {
        self.registry.get(identifier)
    }

    /// Put the current contributor and move to next one. Return the participant that is skipped.
    /// The skipped participant needs to be registered again.
    pub fn skip_current_contributor(&mut self) -> Result<P, CeremonyError> {
        let participant = self.queue.pop().ok_or(CeremonyError::WaitingQueueEmpty)?;
        Ok(self
            .registry
            .unregister(&participant)
            .expect("participant in the queue should be registered"))
    }
}
