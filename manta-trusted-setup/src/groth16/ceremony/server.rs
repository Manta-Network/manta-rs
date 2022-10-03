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
    ceremony::{
        registry::Registry,
        signature::SignedMessage,
        util::{deserialize_from_file, serialize_into_file},
    },
    groth16::{
        ceremony::{
            coordinator::Coordinator,
            message::{ContributeRequest, QueryRequest, QueryResponse},
            Ceremony, CeremonyError, Metadata, Participant as _, UnexpectedError,
        },
        mpc::State,
    },
};
use alloc::sync::Arc;
use core::ops::Deref;
use manta_util::{
    serde::{de::DeserializeOwned, Serialize},
    BoxArray,
};
use parking_lot::Mutex;
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

/// Server
pub struct Server<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Coordinator
    coordinator: Arc<Mutex<Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>>>,

    /// Recovery directory path
    recovery_directory: PathBuf,
}

impl<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
    Server<C, R, LEVEL_COUNT, CIRCUIT_COUNT>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Builds a ['Server`] with initial `state`, `challenge`, a loaded `registry`, and a
    /// `recovery_directory`.
    #[inline]
    pub fn new(
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
        registry: R,
        recovery_directory: PathBuf,
        metadata: Metadata,
    ) -> Self {
        Self {
            coordinator: Arc::new(Mutex::new(Coordinator::new(
                registry, state, challenge, metadata,
            ))),
            recovery_directory,
        }
    }

    /// Recovers from a disk file at `path` and use `recovery_directory` as the backup directory.
    #[inline]
    pub fn recover<P>(path: P, recovery_directory: PathBuf) -> Result<Self, CeremonyError<C>>
    where
        P: AsRef<Path>,
        Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>: DeserializeOwned,
    {
        Ok(Self {
            coordinator: Arc::new(Mutex::new(
                deserialize_from_file(path)
                    .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?,
            )),
            recovery_directory,
        })
    }

    /// Gets the server state size and the current nonce of the participant.
    #[inline]
    pub async fn start(
        self,
        request: C::Identifier,
    ) -> Result<(Metadata, C::Nonce), CeremonyError<C>>
    where
        C::Nonce: Clone,
    {
        let coordinator = self.coordinator.lock();
        Ok((
            coordinator.metadata().clone(),
            coordinator
                .registry()
                .get(&request)
                .ok_or(CeremonyError::NotRegistered)?
                .nonce()
                .clone(),
        ))
    }

    /// Queries the server state
    #[inline]
    pub async fn query(
        self,
        request: SignedMessage<C, C::Identifier, QueryRequest>,
    ) -> Result<QueryResponse<C>, CeremonyError<C>>
    where
        C::Challenge: Clone,
    {
        let mut coordinator = self.coordinator.lock();
        let priority = coordinator.preprocess_request(&request)?;
        let position = coordinator
            .queue_mut()
            .push_back_if_missing(priority.into(), request.into_identifier());
        if position == 0 {
            Ok(QueryResponse::State(coordinator.round_state()))
        } else {
            Ok(QueryResponse::QueuePosition(position as u64))
        }
    }

    /// Processes a request to update the MPC state and removes the participant if the state was
    /// updated successfully. If the update succeeds, the current coordinator is saved to disk.
    #[inline]
    pub async fn update(
        self,
        request: SignedMessage<C, C::Identifier, ContributeRequest<C>>,
    ) -> Result<(), CeremonyError<C>>
    where
        Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>: Serialize,
    {
        let mut coordinator = self.coordinator.lock();
        coordinator.preprocess_request(&request)?;
        let (identifier, message) = request.into_inner();
        coordinator.update(
            &identifier,
            BoxArray::from_vec(message.state),
            BoxArray::from_vec(message.proof),
        )?;
        serialize_into_file(
            OpenOptions::new().write(true).create_new(true),
            &Path::new(&self.recovery_directory)
                .join(format!("transcript{}.data", coordinator.round())),
            &coordinator.deref(),
        )
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
        println!("{} participants have contributed.", coordinator.round());
        Ok(())
    }
}
