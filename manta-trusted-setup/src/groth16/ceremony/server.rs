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
        util::deserialize_from_file,
    },
    groth16::{
        ceremony::{
            coordinator::{preprocess_request, save_registry, LockQueue, StateChallengeProof},
            log::{info, warn},
            message::{ContributeRequest, ContributeResponse, QueryRequest, QueryResponse},
            Ceremony, CeremonyError, CeremonySize, Metadata, UnexpectedError,
        },
        mpc::{Proof, State, StateSize},
    },
};
use alloc::sync::Arc;
use core::{
    fmt::{Debug, Display},
    time::Duration,
};
use manta_util::{
    into_array_unchecked,
    serde::{de::DeserializeOwned, Serialize},
    BoxArray,
};
use parking_lot::Mutex;
use std::{io::Error, path::PathBuf};
use tokio::task;

#[cfg(feature = "csv")]
use crate::ceremony::registry::csv::Record;

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

    /// Recovery Directory Path
    recovery_directory: PathBuf,

    /// Registry Path
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

    /// Recovers from disk files at `path` and uses `path` as the backup directory.
    #[inline]
    pub fn recover(
        path: PathBuf,
        registry_path: PathBuf,
        contribution_time_limit: Duration,
    ) -> Result<Self, CeremonyError<C>>
    where
        C::Challenge: DeserializeOwned + Send,
        C::Identifier: Copy + Debug + Send,
        C::Nonce: Send,
        R::Registry: DeserializeOwned + Send,
        <R::Record as Record<C::Identifier, C::Participant>>::Error: Debug,
        C: 'static,
        R: 'static,
    {
        let mut round_number_path = path.clone();
        round_number_path.push(r"round_number");
        let round_number: u64 = deserialize_from_file(round_number_path)
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
        println!("Recovering a ceremony at round {:?}", round_number);
        let mut names_path = path.clone();
        names_path.push("circuit_names");
        let names: Vec<String> = deserialize_from_file(names_path)
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
        let mut states = Vec::<State<C>>::new();
        let mut challenges = Vec::<C::Challenge>::new();
        let mut proofs = Vec::<Proof<C>>::new();
        for name in names.into_iter() {
            let state: State<C> = deserialize_from_file(filename_format(
                &path,
                name.clone(),
                "state".to_string(),
                round_number,
            ))
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
            states.push(state);
            let challenge: C::Challenge = deserialize_from_file(filename_format(
                &path,
                name.clone(),
                "challenge".to_string(),
                round_number,
            ))
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
            challenges.push(challenge);
            if round_number > 0 {
                let latest_proof: Proof<C> = deserialize_from_file(filename_format(
                    &path,
                    name,
                    "proof".to_string(),
                    round_number,
                ))
                .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
                proofs.push(latest_proof);
            }
        }
        let latest_proof = match round_number {
            0 => None,
            _ => Some(BoxArray::from(into_array_unchecked(proofs))),
        };
        let registry: R::Registry = deserialize_from_file(filename_format(
            &path,
            "".to_string(),
            "registry".to_string(),
            round_number,
        ))
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
        let metadata: Metadata = compute_metadata(contribution_time_limit, &states);
        let server = Self {
            lock_queue: Default::default(),
            registry: Arc::new(Mutex::new(registry)),
            sclp: Arc::new(Mutex::new(StateChallengeProof::new_unchecked(
                BoxArray::from(into_array_unchecked(states)),
                BoxArray::from(into_array_unchecked(challenges)),
                latest_proof,
                round_number,
            ))),
            metadata,
            recovery_directory: path,
            registry_path,
        };
        let server_clone = server.clone();
        task::spawn(async move { server_clone.update_registry().await });
        Ok(server)
    }

    /// Returns the metadata for this ceremony.
    #[inline]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Processes a `start` request and returns the ceremony metadata.
    #[inline]
    pub async fn start(
        self,
        request: C::Identifier,
    ) -> Result<(Metadata, C::Nonce), CeremonyError<C>> {
        let _ = request;
        Ok((self.metadata().clone(), C::Nonce::default()))
    }

    /// Processes a `start` request and returns the ceremony metadata.
    #[inline]
    pub async fn start_endpoint(
        self,
        request: C::Identifier,
    ) -> Result<Result<(Metadata, C::Nonce), CeremonyError<C>>, Error> {
        let response = self.start(request).await;
        Ok(response)
    }

    /// Queries the server state. First bool represents whether the participant who posted
    /// the query got enqueued. Second bool represents whether the lock has been updated.
    #[inline]
    pub async fn query(
        self,
        request: SignedMessage<C, C::Identifier, QueryRequest>,
    ) -> Result<(bool, bool, QueryResponse<C>, C::Participant), CeremonyError<C>>
    where
        C::Challenge: Clone,
        C::Participant: Clone,
    {
        let mut registry = self.registry.lock();
        let priority = preprocess_request::<C, _, _>(&mut *registry, &request)?;
        let mut lock_queue = self.lock_queue.lock();
        let identifier = request.into_identifier();
        let has_lock = lock_queue.has_lock(&identifier, &self.metadata, &mut *registry);
        let participant = registry
            .get(&identifier)
            .expect("Getting participant from valid identifier is not supposed to fail.")
            .clone();
        if has_lock.1.is_ok() {
            return Ok((
                false,
                has_lock.0,
                QueryResponse::State(self.sclp.lock().round_state()),
                participant,
            ));
        }
        let (enqueued, position) = lock_queue
            .queue_mut()
            .push_back_if_missing(priority.into(), identifier);
        Ok((
            enqueued,
            has_lock.0,
            QueryResponse::QueuePosition(position as u64),
            participant,
        ))
    }

    /// Queries the server state and logs any changes to the lock and the queue.
    #[inline]
    pub async fn query_endpoint(
        self,
        request: SignedMessage<C, C::Identifier, QueryRequest>,
    ) -> Result<Result<QueryResponse<C>, CeremonyError<C>>, Error>
    where
        C::Challenge: Clone,
        C::Participant: Clone + Display,
    {
        let response = match self.query(request).await {
            Ok((enqueued, lock_changed, response, participant)) => {
                if lock_changed {
                    let _ = info!("[ACTION] Lock updated.");
                }
                if enqueued {
                    if let QueryResponse::QueuePosition(position) = response {
                        let _ = info!(
                            "[ACTION] Enqueued participant {} in position {}.",
                            participant, position
                        );
                    }
                }
                if let QueryResponse::State(_) = response {
                    let _ = info!(
                        "[RESPONSE] Responding to query from participant {} with state.",
                        participant
                    );
                }
                Ok(response)
            }
            Err(e) => Err(e),
        };
        Ok(response)
    }

    /// Updates the registry.
    #[inline]
    pub async fn update_registry(&self)
    where
        C: 'static,
        C::Nonce: Send,
        R: 'static,
        R::Registry: Send,
        <R::Record as Record<R::Identifier, R::Participant>>::Error: Debug,
    {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let _ = info!("[ACTION] Updating participant registry.");
            let registry_path = self.registry_path.clone();
            let registry = self.registry.clone();
            match task::spawn_blocking(move || {
                load_append_entries::<_, _, R::Record, _, _>(&registry_path, &mut *registry.lock())
                    .map_err(|_| CeremonyError::<C>::Unexpected(UnexpectedError::Serialization))
            })
            .await
            .map_err(|_| CeremonyError::<C>::Unexpected(UnexpectedError::TaskError))
            {
                Ok(Ok(added)) => {
                    let _ = info!("[ACTION] Registry successfully updated. {} New entries added", added);
                },
                Ok(Err(CeremonyError::Unexpected(UnexpectedError::Serialization))) => {
                    let _ = warn!("[ERROR] Unable to update registry. Serialization error.");
                },
                _ => {
                    let _ = warn!("[ERROR] Unable to update registry. Task error.");
                },
            }
        }
    }

    /// Processes a request to update the MPC state and removes the participant if the state was
    /// updated successfully. If the update succeeds, the current coordinator is saved to disk.
    #[inline]
    pub async fn update(
        self,
        request: SignedMessage<C, C::Identifier, ContributeRequest<C>>,
    ) -> Result<ContributeResponse<C>, CeremonyError<C>>
    where
        C: 'static,
        C::Challenge: Clone + Send + Serialize,
        C::ContributionHash: AsRef<[u8]>,
        C::Identifier: Send,
        C::Nonce: Send,
        C::Participant: Clone + Display,
        R: 'static,
        R::Registry: Send + Serialize,
    {
        let _ = info!("[REQUEST] Preprocessing `update` request: checking signature and nonce.");
        let (identifier, message, participant, has_been_updated) = {
            let mut registry = self.registry.lock();
            preprocess_request(&mut *registry, &request)?;
            let (identifier, message) = request.into_inner();
            let has_lock =
                self.lock_queue
                    .lock()
                    .has_lock(&identifier, &self.metadata, &mut *registry);
            has_lock.1?;
            let participant = registry
                .get(&identifier)
                .expect("Getting participant from valid identifier should not fail.")
                .clone();
            (identifier, message, participant, has_lock.0)
        };
        if has_been_updated {
            let _ = info!("[ACTION] Lock updated.");
        }
        let _ = info!(
            "[REQUEST] processing `update` from participant: {}.",
            participant
        );
        let sclp = self.sclp.clone();
        let recovery_directory = self.recovery_directory.clone();

        let (round, challenge) = task::spawn_blocking(move || {
            sclp.lock().update(
                BoxArray::from_vec(message.state),
                BoxArray::from_vec(message.proof),
                recovery_directory,
            )
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))??;
        let registry = self.registry.clone();
        let lock_queue = self.lock_queue.clone();
        let recovery_directory = self.recovery_directory.clone();
        task::spawn_blocking(move || -> Result<(), CeremonyError<C>> {
            let mut registry = registry.lock();
            match registry.get_mut(&identifier) {
                Some(participant) => participant.set_contributed(),
                _ => {
                    return Err(CeremonyError::Unexpected(
                        UnexpectedError::MissingRegisteredParticipant,
                    ))
                }
            }
            lock_queue.lock().update_expired_lock(&mut *registry);
            save_registry::<R::Registry, C>(&registry, &recovery_directory, round);
            Ok(())
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))??;
        let _ = info!("[ACTION] Lock updated.");
        let contribute_response = ContributeResponse {
            index: round,
            challenge: challenge.to_vec(),
        };
        let _ = info!(
            "[RESPONSE] responding to successful `update` number {} from participant \n\
            {}{} with the contribution hash: {}",
            round,
            "                                      ",
            participant,
            hex::encode(C::contribution_hash(&contribute_response))
        );
        Ok(contribute_response)
    }

    /// Processes a request to update the MPC state and removes the participant if the state was
    /// updated successfully. If the update succeeds, the current coordinator is saved to disk.
    #[inline]
    pub async fn update_endpoint(
        self,
        request: SignedMessage<C, C::Identifier, ContributeRequest<C>>,
    ) -> Result<Result<ContributeResponse<C>, CeremonyError<C>>, Error>
    where
        C: 'static,
        C::Challenge: Clone + Send + Serialize,
        C::ContributionHash: AsRef<[u8]>,
        C::Identifier: Send,
        C::Nonce: Debug + Send,
        C::Participant: Clone + Display,
        R: 'static,
        R::Registry: Send + Serialize,
    {
        let response = self.update(request).await;
        match &response {
            Err(CeremonyError::Timeout) => {
                let _ = warn!("[ERROR] Timeout during contribution.");
            }
            Err(CeremonyError::BadRequest) => {
                let _ = warn!("[ERROR] Invalid contribution.");
            }
            Err(e) => {
                let _ = warn!("[ERROR] Unexpected error {:?}", e);
            }
            _ => {}
        };
        Ok(response)
    }
}

/// Produces [`Metadata`] from a slice of [`State`]s and specified contribution time limit.
pub fn compute_metadata<C>(contribution_time_limit: Duration, states: &[State<C>]) -> Metadata
where
    C: Ceremony,
{
    Metadata {
        ceremony_size: CeremonySize::from(
            states
                .iter()
                .map(|s| StateSize::from_proving_key(&s.0))
                .collect::<Vec<_>>(),
        ),
        contribution_time_limit,
    }
}

/// Filename formatting for saving/recovering server. The `kind` may be
/// `state`, `challenge`, `proof`, `registry`. For `registry` the `name`
/// should be "".
pub fn filename_format(
    folder_path: &PathBuf,
    name: String,
    kind: String,
    round_number: u64,
) -> PathBuf {
    let mut path = folder_path.clone();
    path.push(format!("{}_{}_{}", name, kind, round_number));
    path
}
