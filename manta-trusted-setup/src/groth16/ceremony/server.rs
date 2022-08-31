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

//! Trusted Setup Server

use crate::groth16::{
    ceremony::{
        coordinator::{ChallengeArray, Coordinator, StateArray},
        message::Signed,
        registry::Registry,
        signature::{check_nonce, verify, Nonce as _},
        Ceremony, Nonce, Participant,
    },
    mpc::StateSize,
    CeremonyError,
};
use manta_util::Array;
use std::sync::{Arc, Mutex};

pub struct Server<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant, Nonce<C>>,
{
    /// Coordinator
    coordinator: Arc<Mutex<Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>>>,

    /// Recovery directory path
    recovery_path: String,
}

impl<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
    Server<C, R, LEVEL_COUNT, CIRCUIT_COUNT>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant, Nonce<C>>,
{
    /// Builds a ['Server`] with initial `state`, `challenge`, a loaded `registry`, and a `recovery_path`.
    #[inline]
    pub fn new(
        state: StateArray<C, CIRCUIT_COUNT>,
        challenge: ChallengeArray<C, CIRCUIT_COUNT>,
        registry: R,
        recovery_path: String,
        size: Array<StateSize, CIRCUIT_COUNT>,
    ) -> Self {
        let coordinator = Coordinator {
            registry,
            queue: Default::default(),
            participant_lock: Default::default(),
            state,
            challenge,
            latest_contributor: None,
            latest_proof: None,
            size,
            round: 0,
        };
        Self {
            coordinator: Arc::new(Mutex::new(coordinator)),
            recovery_path,
        }
    }

    /// Preprocess a request by checking nonce and verifying signature.
    #[inline]
    pub fn process_request<T>(
        registry: &mut R,
        request: &Signed<T, C>,
    ) -> Result<(), CeremonyError<C>> {
        if registry.has_contributed(&request.identifier) {
            return Err(CeremonyError::AlreadyContributed);
        }

        let participant_nonce = registry
            .get_nonce(&request.identifier)
            .ok_or_else(|| CeremonyError::NotRegistered)?;

        if !check_nonce(&participant_nonce, &request.nonce) {
            return Err(CeremonyError::NonceNotInSync(participant_nonce));
        };

        let participant = match registry.get(&request.identifier) {
            Some(participant) => participant,
            None => unreachable!("participant registration has been checked"),
        };

        verify(
            participant.verifying_key(),
            participant_nonce,
            &request.message,
            &request.signature,
        )
        .map_err(|_| CeremonyError::BadRequest)?;

        registry.set_nonce(&request.identifier, participant_nonce.increment());
        Ok(())
    }
}
