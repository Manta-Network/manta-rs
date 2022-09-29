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
        participant::Participant,
        registry::{self, csv::load_append_entries, Registry},
        signature::SignedMessage,
        util::{deserialize_from_file, serialize_into_file},
    },
    groth16::{
        ceremony::{
            message::{ContributeRequest, ContributeResponse, QueryRequest, QueryResponse},
            Ceremony, CeremonyError, Metadata, UnexpectedError,
        },
        mpc::State,
    },
};
use alloc::sync::Arc;
use manta_util::{
    serde::{de::DeserializeOwned, Serialize},
    BoxArray,
};
use parking_lot::Mutex;
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};
use tokio::task;

use super::coordinator::{preprocess_request, LockQueue, StateChallengeProof};

/// Server
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Server<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
    R: registry::Configuration<Identifier = C::Identifier, Participant = C::Participant>,
{
    /// Lock and Queue
    lock_queue: Arc<Mutex<LockQueue<C, LEVEL_COUNT>>>,

    /// Participant Registry
    registry: Arc<Mutex<R::Registry>>,

    /// State, Challenge and Latest Proof
    sclp: Arc<Mutex<StateChallengeProof<C, CIRCUIT_COUNT>>>,

    /// Ceremony Metadata
    metadata: Metadata,

    /// Recovery directory path
    recovery_directory: PathBuf,

    /// Registry path
    registry_path: PathBuf,
}

impl<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
    Server<C, R, LEVEL_COUNT, CIRCUIT_COUNT>
where
    C: Ceremony,
    R: registry::Configuration<Identifier = C::Identifier, Participant = C::Participant>,
{
    /// Builds a ['Server`] with initial `state`, `challenge`, a loaded `registry`, and a
    /// `recovery_directory`.
    #[inline]
    pub fn new(
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
        registry: R::Registry,
        recovery_directory: PathBuf,
        metadata: Metadata,
        registry_path: PathBuf,
    ) -> Self {
        assert!(
            metadata.ceremony_size.matches(state.as_slice()),
            "Mismatch of metadata `{:?}` and state.",
            metadata,
        );
        Self {
            lock_queue: Default::default(),
            registry: Arc::new(Mutex::new(registry)),
            sclp: Arc::new(Mutex::new(StateChallengeProof::new(state, challenge))),
            metadata,
            recovery_directory,
            registry_path,
        }
    }

    /// Recovers from a disk file at `path` and use `recovery_directory` as the backup directory.
    #[inline]
    pub fn recover<P>(path: P, recovery_directory: PathBuf) -> Result<Self, CeremonyError<C>>
    where
        P: AsRef<Path>,
        Self: DeserializeOwned,
    {
        let mut new_server: Self = deserialize_from_file(path)
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
        new_server.recovery_directory = recovery_directory;
        Ok(new_server)
    }

    /// Returns the metadata for this ceremony.
    #[inline]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Gets the server state size and the current nonce of the participant.
    #[inline]
    pub async fn start(
        self,
        request: C::Identifier,
    ) -> Result<(Metadata, C::Nonce), CeremonyError<C>>
    where
        C::Nonce: Clone + Send, 
    {
        let nonce = self
            .registry
            .lock()
            .get(&request)
            .ok_or(CeremonyError::NotRegistered)?
            .nonce()
            .clone();
        task::spawn(async {
            if self.update_registry().await.is_err() {
                todo!() // We need to add logging here
            }
        });
        Ok((self.metadata().clone(), nonce))
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
        let priority = preprocess_request(&mut *self.registry.lock(), &request)?;
        let position = self
            .lock_queue
            .lock()
            .queue_mut()
            .push_back_if_missing(priority.into(), request.into_identifier());
        if position == 0 {
            Ok(QueryResponse::State(self.sclp.lock().round_state()))
        } else {
            Ok(QueryResponse::QueuePosition(position as u64))
        }
    }

    /// Updates the registry.
    #[inline]
    pub async fn update_registry(&self) -> Result<(), CeremonyError<C>>
    where
        C::Nonce: Send,
        R::Registry: Send,
        C::Identifier: Send,
        C::Challenge: Send,
        C: 'static,
        R: 'static,
    {
        let registry_path = self.registry_path.clone();
        let registry = self.registry.clone();
        task::spawn_blocking(move || {
            load_append_entries::<_, _, R::Record, _, _>(&registry_path, &mut *registry.lock())
                .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))?
    }

    /// Saves `self` into `self.recovery_directory`.
    pub async fn save_server(&self, round: u64) -> Result<(), CeremonyError<C>>
    where
        Self: Serialize,
        C::Challenge: Clone + Send,
        C::Nonce: Send,
        R::Registry: Send,
        C::Identifier: Send,
        C: 'static,
        R: 'static,
    {
        let server = self.clone();
        task::spawn_blocking(move || {
            serialize_into_file(
                OpenOptions::new().write(true).create_new(true),
                &Path::new(&server.recovery_directory).join(format!("transcript{}.data", round)),
                &server,
            )
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))?
    }

    /// Processes a request to update the MPC state and removes the participant if the state was
    /// updated successfully. If the update succeeds, the current coordinator is saved to disk.
    #[inline]
    pub async fn contribute(
        self,
        request: SignedMessage<C, C::Identifier, ContributeRequest<C>>,
    ) -> Result<ContributeResponse<C>, CeremonyError<C>>
    where
        Self: Serialize,
        C: 'static,
        C::Challenge: Clone + Send,
        C::Identifier: Send,
        C::Nonce: Send,
        StateChallengeProof<C, CIRCUIT_COUNT>: Send,
        R::Registry: Send,
        R: 'static,
    {
        let mut registry = self.registry.lock();
        preprocess_request(&mut *registry, &request)?;
        let (identifier, message) = request.into_inner();
        self.lock_queue
            .lock()
            .update(&identifier, &mut *registry, self.metadata())?;
        drop(registry);
        let sclp = self.sclp.clone();
        let round = task::spawn_blocking(move || {
            sclp.lock().update(
                BoxArray::from_vec(message.state),
                BoxArray::from_vec(message.proof),
            )
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))??;
        self.save_server(round).await?;
        println!("{} participants have contributed.", round);
        self.update_registry().await?;
        Ok(ContributeResponse {
            index: round,
            challenge: self.sclp.lock().challenge().to_vec(),
        })
    }
}
