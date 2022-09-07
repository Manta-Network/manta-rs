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
    groth16::{
        ceremony::{
            message::{MPCState, Signed},
            registry::Registry,
            serde::{deserialize_array, serialize_array},
            signature::{check_nonce, verify},
            Ceremony, CeremonyError, Participant, Queue, UserPriority,
        },
        mpc::{Proof, State, StateSize},
    },
    mpc::Challenge,
};
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_util::{time::lock::Timed, Array, BoxArray};

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
                Challenge<C>: Serialize,
                C::Participant: Serialize,
                State<C::Pairing>: CanonicalSerialize,
                Proof<C::Pairing>: Serialize,
            ",
            deserialize = r"
                R: Deserialize<'de>,
                Challenge<C>: Deserialize<'de>,
                C::Participant: Deserialize<'de>,
                State<C::Pairing>: CanonicalDeserialize,
                Proof<C::Pairing>: Deserialize<'de>,
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
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serialize_array::<State<C::Pairing>, _, CIRCUIT_COUNT>",
            deserialize_with = "deserialize_array::<'de, _, State<C::Pairing>, CIRCUIT_COUNT>"
        )
    )]
    state: BoxArray<State<C::Pairing>, CIRCUIT_COUNT>,

    /// Challenge
    challenge: BoxArray<Challenge<C>, CIRCUIT_COUNT>,

    /// Latest Contributor
    ///
    /// This participant was the last one to perform a successful contribution to the ceremony.
    latest_contributor: Option<C::Participant>,

    /// Latest Proof
    // #[cfg_attr(
    //     feature = "serde",
    //     serde(
    //         serialize_with = "serialize_array::<Proof<C::Pairing>, _, CIRCUIT_COUNT>",
    //         deserialize_with = "deserialize_array::<'de, _, Proof<C::Pairing>, CIRCUIT_COUNT>"
    //     )
    // )]
    latest_proof: Option<BoxArray<Proof<C::Pairing>, CIRCUIT_COUNT>>, // TODO: Implement serialize

    /// State Sizes
    size: Array<StateSize, CIRCUIT_COUNT>,

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
        state: BoxArray<State<C::Pairing>, CIRCUIT_COUNT>,
        challenge: BoxArray<Challenge<C>, CIRCUIT_COUNT>,
        size: Array<StateSize, CIRCUIT_COUNT>,
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

    /// Returns the state size.
    #[inline]
    pub fn size(&self) -> &Array<StateSize, CIRCUIT_COUNT> {
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

    ///
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
        if self.registry.has_contributed(&request.identifier) {
            return Err(CeremonyError::AlreadyContributed);
        }
        let participant = self
            .registry
            .get_mut(&request.identifier)
            .ok_or_else(|| CeremonyError::NotRegistered)?;
        let participant_nonce = participant.get_nonce();
        if !check_nonce(&participant_nonce, &request.nonce) {
            return Err(CeremonyError::NonceNotInSync(participant_nonce));
        };
        verify::<T, C::SignatureScheme>(
            participant.verifying_key(),
            participant_nonce,
            &request.message,
            &request.signature,
        )
        .map_err(|_| CeremonyError::BadRequest)?;
        participant.increment_nonce();
        Ok(participant.level())
    }
}
