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

use crate::{
    groth16::{
        ceremony::{
            coordinator::{ChallengeArray, Coordinator, StateArray},
            message::{QueryRequest, QueryResponse, ServerSize, Signed},
            registry::Registry,
            signature::{check_nonce, verify, Nonce as _},
            Ceremony, CeremonyError, Nonce, Participant,
        },
        mpc::{State, StateSize},
    },
    mpc::Challenge,
};
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use manta_util::{serde::Serialize, Array};
use std::sync::{Arc, Mutex};

use super::Signature;

pub struct Server<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
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
    R: Registry<C::Identifier, C::Participant>,
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
    pub fn preprocess_request<T>(
        registry: &mut R,
        request: &Signed<T, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        T: Serialize,
    {
        if registry.has_contributed(&request.identifier) {
            return Err(CeremonyError::AlreadyContributed);
        }
        let participant_nonce = registry
            .get(&request.identifier)
            .ok_or_else(|| CeremonyError::NotRegistered)?
            .get_nonce();
        if !check_nonce(&participant_nonce, &request.nonce) {
            return Err(CeremonyError::NonceNotInSync(participant_nonce));
        };
        let mut participant = match registry.get(&request.identifier) {
            Some(participant) => participant,
            None => unreachable!("participant registration has been checked"),
        };
        verify::<T, C::SignatureScheme>(
            participant.verifying_key(),
            participant_nonce,
            &request.message,
            &request.signature,
        )
        .map_err(|_| CeremonyError::BadRequest)?;
        participant.increment_nonce();
        Ok(())
    }

    /// Gets the server state size and the current nonce of the participant.
    #[inline]
    pub async fn start(
        self,
        request: C::Identifier,
    ) -> Result<(ServerSize<CIRCUIT_COUNT>, Nonce<C>), CeremonyError<C>> {
        let coordinator = self
            .coordinator
            .lock()
            .expect("acquiring a lock is not allowed to fail");
        Ok((
            coordinator.size.clone().into(),
            coordinator
                .nonce(&request)
                .ok_or_else(|| CeremonyError::NotRegistered)?,
        ))
    }

    /// Queries the server state
    #[inline]
    pub async fn query(
        self,
        request: Signed<QueryRequest, C>,
    ) -> Result<QueryResponse<C, CIRCUIT_COUNT>, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        State<C::Pairing>: CanonicalSerialize + CanonicalDeserialize,
        Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
    {
        let mut coordinator = self.coordinator.lock();
        Self::preprocess_request(&mut coordinator.registry, &request)?;
        if !coordinator.is_in_queue(&request.identifier)? {
            coordinator.enqueue_participant(&request.identifier)?;
        }
        if coordinator.is_next(&request.identifier) {
            Ok(QueryResponse::Mpc(coordinator.state_and_challenge()))
        } else {
            Ok(QueryResponse::QueuePosition(
                coordinator
                    .position(
                        coordinator
                            .get_participant(&request.identifier)
                            .expect("Participant existence is checked in `process_request`."),
                    )
                    .expect("Participant should be always in the queue here"),
            ))
        }
    }
}
