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
        util::{
            canonical_deserialize_from_file, canonical_serialize_into_file, deserialize_from_file,
            serialize_into_file,
        },
    },
    groth16::{
        ceremony::{
            coordinator,
            log::{info, warn},
            message::{ContributeRequest, ContributeResponse, QueryRequest, QueryResponse},
            Ceremony, CeremonyError, CeremonySize, Configuration, Metadata, UnexpectedError,
        },
        kzg,
        mpc::{self, Proof, State, StateSize},
        ppot::serialization::{read_subaccumulator, Compressed},
    },
    mpc::ChallengeType,
};
use alloc::sync::Arc;
use core::fmt::Debug;
use manta_crypto::arkworks::{
    bn254::{G1Affine, G2Affine},
    pairing::Pairing,
};
use manta_util::{
    into_array_unchecked,
    serde::{de::DeserializeOwned, Serialize},
    Array, BoxArray,
};
use parking_lot::Mutex;
use std::{fs::OpenOptions, path::Path, time::Duration};
use tokio::task;

#[cfg(feature = "csv")]
use crate::ceremony::registry::csv::{load, Record};

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

    /// Recovery Directory Path
    recovery_directory: String,

    /// Registry Path
    registry_path: String,
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
        recovery_directory: String,
        metadata: Metadata,
        registry_path: String,
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

    /// Recovers from a disk file at `path` and uses `recovery_directory` as the backup directory.
    #[inline]
    pub fn recover<P>(path: P, recovery_directory: String) -> Result<Self, CeremonyError<C>>
    where
        P: AsRef<Path>,
        C::Challenge: DeserializeOwned,
        R::Registry: DeserializeOwned,
    {
        let folder_path = path.as_ref().display();
        let round_number: u64 =
            canonical_deserialize_from_file(format!("{}{}", folder_path, "/round_number"))
                .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
        println!("Recovering a ceremony at round {:?}", round_number);

        let names: Vec<String> = C::circuits().into_iter().map(|p| p.1).collect(); // TODO: This wastefully generates the circuit descriptions, perhaps break into `circuits()` and `circuit_names()` in Ceremony trait
        let mut states = Vec::<State<C>>::new();
        let mut challenges = Vec::<C::Challenge>::new();
        let mut proofs = Vec::<Proof<C>>::new();

        for name in names.into_iter() {
            let state: State<C> = deserialize_from_file(filename_format(
                folder_path.to_string(),
                name.clone(),
                "state".to_string(),
                round_number,
            ))
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
            states.push(state);

            let challenge: C::Challenge = deserialize_from_file(filename_format(
                folder_path.to_string(),
                name.clone(),
                "challenge".to_string(),
                round_number,
            ))
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
            challenges.push(challenge);

            if round_number > 0 {
                let latest_proof: Proof<C> = deserialize_from_file(filename_format(
                    folder_path.to_string(),
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
            folder_path.to_string(),
            "".to_string(),
            "registry".to_string(),
            round_number,
        ))
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;

        // To avoid cloning states below, compute metadata now.
        let metadata: Metadata = compute_metadata(Duration::new(20, 0), &states); // changed lock time

        Ok(Self {
            lock_queue: Default::default(),
            registry: Arc::new(Mutex::new(registry)),
            sclp: Arc::new(Mutex::new(StateChallengeProof::new_unchecked(
                BoxArray::from(into_array_unchecked(states)),
                BoxArray::from(into_array_unchecked(challenges)),
                latest_proof,
                round_number,
            ))),
            metadata,
            recovery_directory: recovery_directory.clone(),
            registry_path: recovery_directory, // TODO: Do we need a separate registry path?
        })
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
        C::Nonce: Clone + Debug + Send,
        R::Registry: Send,
        C::Challenge: Send,
        C::Identifier: Debug + Send,
        C: 'static,
        R: 'static,
    {
        let _ = info!(
            "[REQUEST] processing `start`, from participant with identifier:  {:?}.",
            request
        );
        let nonce = self
            .registry
            .lock()
            .get(&request)
            .ok_or(CeremonyError::NotRegistered)?
            .nonce()
            .clone();
        let metadata = self.metadata().clone();
        task::spawn(async move {
            if self.update_registry().await.is_err() {
                let _ = warn!("Unable to update registry.");
            }
        });
        let _ = info!(
            "[RESPONSE] responding to `start` with: {:?}.",
            (&metadata, &nonce)
        );
        Ok((metadata, nonce))
    }

    /// Queries the server state
    #[inline]
    pub async fn query(
        self,
        request: SignedMessage<C, C::Identifier, QueryRequest>,
    ) -> Result<QueryResponse<C>, CeremonyError<C>>
    where
        C::Challenge: Clone + Debug,
        State<C>: Debug,
    {
        let _ = info!("[REQUEST] processing `query`");
        let priority = preprocess_request(
            &mut *self.registry.lock(),
            &mut *self.lock_queue.lock(),
            self.metadata(),
            &request,
        )?;

        let position =self.lock_queue.lock()
                .queue_mut()
                .push_back_if_missing(priority.into(), request.into_identifier());
        if position == 0 {
            let state = self.sclp.lock().round_state();
            let _ = info!("[RESPONSE] responding to `query` with round state.");
            Ok(QueryResponse::State(state))
        } else {
            let _ = info!(
                "[RESPONSE] responding to `query` with queue position: {:?}.",
                &position
            );
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
        let _ = info!("Updating participant registry.");
        let registry_path = self.registry_path.clone();
        let registry = self.registry.clone();
        let _ = task::spawn_blocking(move || {
            load_append_entries::<_, _, R::Record, _, _>(&registry_path, &mut *registry.lock())
                .map_err(|_| CeremonyError::<C>::Unexpected(UnexpectedError::Serialization))
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))?;
        let _ = info!("Registry successfully updated.");
        Ok(())
    }

    /// Saves `self` into `self.recovery_directory`. // TODO: Split across the sclp/registry locks
    pub async fn save_server(&self, round: u64) -> Result<(), CeremonyError<C>>
    where
        C::Challenge: Clone + Send + Serialize,
        C::Nonce: Send,
        R::Registry: Send + Serialize,
        C::Identifier: Send,
        C: 'static,
        R: 'static,
    {
        let _ = info!("Saving server to recovery directory.");
        let registry = self.registry.clone();
        let recovery_directory = self.recovery_directory.clone();
        task::spawn_blocking(move || {
            let registry = registry.lock();
            serialize_into_file(
                OpenOptions::new().write(true).create(true),
                &filename_format(
                    recovery_directory.clone(),
                    "".to_string(),
                    "registry".to_string(),
                    round,
                ),
                &*registry,
            )
            .map_err(|_| CeremonyError::<C>::Unexpected(UnexpectedError::Serialization))
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))?;
        let sclp = self.sclp.clone();
        let recovery_directory = self.recovery_directory.clone();
        let _ = task::spawn_blocking(move || -> Result<(), CeremonyError<C>> {
            let sclp = sclp.lock();
            assert_eq!(round, sclp.round());
            for ((state, challenge), name) in sclp
                .state()
                .iter()
                .zip(sclp.challenge().iter())
                .zip(C::circuits().into_iter().map(|p| p.1))
            {
                serialize_into_file(
                    OpenOptions::new().write(true).truncate(true).create(true),
                    &filename_format(
                        recovery_directory.clone(),
                        name.clone(),
                        "state".to_string(),
                        round,
                    ),
                    state,
                )
                .expect("Writing state to disk should succeed.");

                serialize_into_file(
                    OpenOptions::new().write(true).truncate(true).create(true),
                    &filename_format(
                        recovery_directory.clone(),
                        name.clone(),
                        "challenge".to_string(),
                        round,
                    ),
                    &challenge,
                )
                .expect("Writing challenge to disk should succeed.");
            }

            if round > 0 {
                for (proof, name) in sclp
                    .latest_proof()
                    .as_ref()
                    .unwrap()
                    .iter()
                    .zip(C::circuits().into_iter().map(|p| p.1))
                {
                    serialize_into_file(
                        OpenOptions::new().write(true).truncate(true).create(true),
                        &filename_format(
                            recovery_directory.clone(),
                            name.clone(),
                            "proof".to_string(),
                            round,
                        ),
                        proof,
                    )
                    .expect("Writing proof to disk should succeed.");
                }
            }

            canonical_serialize_into_file(
                OpenOptions::new().write(true).truncate(true).create(true),
                &format!("{}/round_number", recovery_directory),
                &round,
            )
            .expect("Must serialize round number to file");

            Ok(())
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))?;
        let _ = info!("Server successfully saved.");
        Ok(())
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
        C::Challenge: Clone + Debug + Send + Serialize,
        C::Identifier: Send,
        C::Nonce: Send,
        C::Nonce: Debug,
        StateChallengeProof<C, CIRCUIT_COUNT>: Send,
        R::Registry: Send + Serialize,
        R: 'static,
    {
        let _ = info!("[REQUEST] processing `update`");
        let _ = info!("Preprocessing `update` request: checking signature and nonce, updating queue if applicable");
        let (identifier, message) = {
            let mut registry = self.registry.lock();
            preprocess_request(
                &mut *registry,
                &mut *self.lock_queue.lock(),
                self.metadata(),
                &request,
            )?;
            request.into_inner()
        };
        let _ = info!("About to check contribution validity");
        let sclp = self.sclp.clone();
        let round = task::spawn_blocking(move || {
            sclp.lock().update(
                BoxArray::from_vec(message.state),
                BoxArray::from_vec(message.proof),
            )
        })
        .await
        .map_err(|_| CeremonyError::Unexpected(UnexpectedError::TaskError))??;

        // Lock should expire here no matter what
        {
            let mut registry = self.registry.lock();
            match registry.get_mut(&identifier) {
                Some(participant) => participant.set_contributed(),
                _ => {
                    return Err(CeremonyError::Unexpected(
                        UnexpectedError::MissingRegisteredParticipant,
                    ))
                }
            }
            self.lock_queue.lock().update_expired_lock(&mut *registry);
        }

        self.save_server(round).await?;
        
        println!("{} participants have contributed.", round);
        self.update_registry().await?;
        let challenge = self.sclp.lock().challenge().to_vec();
        let _ = info!(
            "[RESPONSE] responding to `update` with: {:?}",
            (round, &challenge)
        );
        tokio::time::sleep(Duration::new(10, 0)).await;

        Ok(ContributeResponse {
            index: round,
            challenge,
        })
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
    folder_path: String,
    name: String,
    kind: String,
    round_number: u64,
) -> String {
    format!("{}/{}_{}_{}", folder_path, name, kind, round_number)
}

/// Prepare by initalizing each circuit's prover key, challenge hash and saving
/// to file. TODO: Currently assumes that the challenge hash type is [u8; 64].
/// Also saves registry to file.
pub fn prepare<C, P, R, T>(phase_one_param_path: String, recovery_path: P, registry_path: P)
where
    C: Ceremony + Configuration + kzg::Configuration + kzg::Size + mpc::ProvingKeyHasher<C>,
    C: mpc::ProvingKeyHasher<C, Output = [u8; 64]>,
    C: ChallengeType<Challenge = Array<u8, 64>>,
    C: Pairing<G1 = G1Affine, G2 = G2Affine>, // TODO: Generalize or make part of a config
    P: AsRef<Path>,
    R: Registry<C::Identifier, C::Participant> + Serialize,
    R: registry::Configuration<
        Identifier = C::Identifier,
        Participant = C::Participant,
        Registry = R,
    >,
    T: Record<C::Identifier, C::Participant>,
    T::Error: Debug,
{
    use memmap::MmapOptions;

    let file = OpenOptions::new()
        .read(true)
        .open(phase_one_param_path)
        .expect("Unable to open phase 1 parameter file in this directory");
    let reader = unsafe {
        MmapOptions::new()
            .map(&file)
            .expect("unable to create memory map for input")
    };
    let powers = read_subaccumulator(&reader, Compressed::No)
        .expect("Cannot read Phase 1 accumulator from file");

    let folder_path = recovery_path.as_ref().display();
    let round_number = 0u64;
    for (circuit, name) in C::circuits().into_iter() {
        println!("Creating proving key for {}", name);
        let (challenge, state): (<C as ChallengeType>::Challenge, State<C>) =
            coordinator::initialize(&powers, circuit);

        serialize_into_file(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create_new(true), // `prepare` should only be called once
            &filename_format(
                folder_path.to_string(),
                name.clone(),
                "state".to_string(),
                round_number,
            ),
            &state,
        )
        .expect("Writing state to disk should succeed.");

        serialize_into_file(
            OpenOptions::new().write(true).truncate(true).create(true),
            &filename_format(
                folder_path.to_string(),
                name,
                "challenge".to_string(),
                round_number,
            ),
            &challenge,
        )
        .expect("Writing challenge to disk should succeed.");
    }
    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &format!("{}/round_number", folder_path),
        &round_number,
    )
    .expect("Must serialize round number to file");

    let registry = load::<C::Identifier, C::Participant, T, R, _>(registry_path).unwrap();
    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &filename_format(
            folder_path.to_string(),
            "".to_string(),
            "registry".to_string(),
            round_number,
        ),
        &registry,
    )
    .expect("Writing registry to disk should succeed.");
}
