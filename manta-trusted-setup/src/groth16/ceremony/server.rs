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
        coordinator::Coordinator,
        message::{ContributeRequest, QueryRequest, QueryResponse, ServerSize, Signed},
        registry::Registry,
        util::log_to_file,
        Ceremony, CeremonyError, Challenge, Nonce, Participant,
    },
    mpc::{State, StateSize},
};
use alloc::sync::Arc;
use core::ops::Deref;
use manta_util::{serde::Serialize, Array, BoxArray};
use parking_lot::Mutex;
use std::path::Path;

/// Server
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
        state: BoxArray<State<C::Configuration>, CIRCUIT_COUNT>,
        challenge: BoxArray<Challenge<C>, CIRCUIT_COUNT>,
        registry: R,
        recovery_path: String,
        size: Array<StateSize, CIRCUIT_COUNT>,
    ) -> Self {
        let coordinator = Coordinator::new(registry, state, challenge, size);
        Self {
            coordinator: Arc::new(Mutex::new(coordinator)),
            recovery_path,
        }
    }

    /// Gets the server state size and the current nonce of the participant.
    #[inline]
    pub async fn start(
        self,
        request: C::Identifier,
    ) -> Result<(ServerSize<CIRCUIT_COUNT>, Nonce<C>), CeremonyError<C>> {
        let coordinator = self.coordinator.lock();
        Ok((
            coordinator.size().clone().into(),
            coordinator
                .registry()
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
        Challenge<C>: Clone,
    {
        let mut coordinator = self.coordinator.lock();
        let priority = coordinator.preprocess_request(&request)?;
        let position = coordinator
            .queue_mut()
            .push_back_if_missing(priority.into(), request.identifier);
        if position == 0 {
            Ok(QueryResponse::Mpc(coordinator.state_and_challenge()))
        } else {
            Ok(QueryResponse::QueuePosition(position))
        }
    }

    /// Processes a request to update the MPC state and remove the participant if successfully updated the state.
    /// If update succeeds, save the current coordinator to disk.
    #[inline]
    pub async fn update(
        self,
        request: Signed<ContributeRequest<C, CIRCUIT_COUNT>, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>: Serialize,
    {
        let mut coordinator = self.coordinator.lock();
        coordinator.preprocess_request(&request)?;
        let contribute_state = request.message.contribute_state;
        coordinator.update(
            &request.identifier,
            contribute_state.state,
            contribute_state.proof,
        )?;
        coordinator
            .participant_mut(&request.identifier)
            .expect("Geting participant should succeed.")
            .set_contributed();
        coordinator.increment_round();
        log_to_file(
            &Path::new(&self.recovery_path).join(format!("transcript{}.data", coordinator.round())),
            &coordinator.deref(),
        );
        println!("{} participants have contributed.", coordinator.round());
        Ok(())
    }
}
