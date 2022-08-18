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

//! Asynchronous Server for Trusted Setup

use crate::{
    ceremony::{
        config::{CeremonyConfig, Challenge, Nonce, ParticipantIdentifier, Proof, State},
        coordinator::Coordinator,
        message::{ContributeRequest, QueryRequest, QueryResponse, Signed},
        registry::{HasContributed, Registry},
        signature::{HasPublicKey, Nonce as _, SignatureScheme},
        CeremonyError,
    },
    util::AsBytes,
};
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::File,
    future::Future,
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};
use tide::{Body, Request, Response};
use tracing::info;

/// Has Nonce
pub trait HasNonce<S>
where
    S: SignatureScheme,
{
    /// Returns the nonce of `self` as a participant.
    fn nonce(&self) -> S::Nonce;

    /// Sets nonce.
    fn set_nonce(&mut self, nonce: S::Nonce);
}

/// Server
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Server<C, const N: usize>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize + CanonicalDeserialize,
    Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
    Proof<C>: CanonicalSerialize + CanonicalDeserialize,
{
    /// Coordinator
    coordinator: Arc<Mutex<Coordinator<C, N, 3>>>,

    /// Recovery Directory Path
    recovery_path: String,
}

impl<C, const N: usize> Server<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize + CanonicalDeserialize,
    Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
    Proof<C>: CanonicalSerialize + CanonicalDeserialize,
{
    /// Builds a [`Server`] with initial `state`, `challenge`, a loaded `registry`, and a `recovery_path`.
    #[inline]
    pub fn new(
        state: [State<C>; 3],
        challenge: [Challenge<C>; 3],
        registry: Registry<ParticipantIdentifier<C>, C::Participant>,
        recovery_path: String,
    ) -> Self {
        Self {
            coordinator: Arc::new(Mutex::new(Coordinator::new(
                0, None, None, state, challenge, registry,
            ))),
            recovery_path,
        }
    }

    /// Preprocesses a request by checking nonce and verifying signature.
    #[inline]
    pub fn preprocess_request<T>(
        &self,
        coordinator: &mut Coordinator<C, N, 3>,
        request: &Signed<T, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        T: Serialize,
    {
        let participant = match coordinator.get_participant_mut(&request.identifier) {
            Some(participant) => participant,
            None => return Err(CeremonyError::NotRegistered),
        };
        let mut nonce = participant.nonce();
        if participant.nonce() != request.nonce {
            return Err(CeremonyError::NonceNotInSync(participant.nonce()));
        }
        C::SignatureScheme::verify(
            &request.message,
            &request.nonce,
            &request.signature,
            &participant.public_key(),
        )
        .map_err(|_| CeremonyError::BadRequest)?;
        nonce.increment();
        participant.set_nonce(nonce);
        Ok(())
    }

    /// Queries the server state.
    #[inline]
    pub async fn query(
        self,
        request: Signed<QueryRequest, C>,
    ) -> Result<QueryResponse<C>, CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
    {
        let mut coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        self.preprocess_request(&mut *coordinator, &request)?;
        if !coordinator.is_in_queue(&request.identifier)? {
            coordinator.enqueue_participant(&request.identifier)?;
        }
        if coordinator.is_next(&request.identifier) {
            Ok(QueryResponse::Mpc(AsBytes::from_actual(
                coordinator.state_and_challenge(),
            )))
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

    /// Processes a request to update the MPC state and remove the participant if successfully updated the state.
    /// If update succeeds, save the current coordinator to disk.
    #[inline]
    pub async fn update(
        self,
        request: Signed<ContributeRequest<C>, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        ContributeRequest<C>: Serialize,
        ParticipantIdentifier<C>: Serialize,
        C::Participant: Serialize,
    {
        let mut coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        self.preprocess_request(&mut *coordinator, &request)?;
        match coordinator.get_participant(&request.identifier) {
            Some(participant) => {
                if participant.has_contributed() {
                    return Err(CeremonyError::<C>::AlreadyContributed); // TODO. Should tell client that you have contributed successfully before.
                }
            }
            None => {
                return Err(CeremonyError::<C>::BadRequest); // TODO
            }
        }
        let state = [
            request
                .message
                .state0
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
            request
                .message
                .state1
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
            request
                .message
                .state2
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
        ];
        let proof = [
            request
                .message
                .proof0
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
            request
                .message
                .proof1
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
            request
                .message
                .proof2
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
        ];
        coordinator.update(&request.identifier, state, proof)?;
        coordinator
            .get_participant_mut(&request.identifier)
            .expect("Geting participant should succeed.")
            .set_contributed();
        coordinator.num_contributions += 1;
        // TODO: checksum
        Self::log_to_file(&coordinator, &self.recovery_path);
        println!(
            "{} participants have contributed.",
            coordinator.num_contributions
        );
        Ok(())
    }

    /// Gets the current nonce of the participant.
    #[inline]
    pub async fn get_nonce(
        self,
        request: ParticipantIdentifier<C>,
    ) -> Result<Nonce<C>, CeremonyError<C>>
    where
        ContributeRequest<C>: Serialize,
        ParticipantIdentifier<C>: Serialize,
    {
        Ok(self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.")
            .get_participant(&request)
            .ok_or(CeremonyError::NotRegistered)?
            .nonce())
    }

    /// Generates log and saves to a disk file.
    #[inline]
    pub fn log_to_file<P: AsRef<Path>>(coordinator: &Coordinator<C, N, 3>, log_dir: P)
    where
        Proof<C>: CanonicalSerialize,
        State<C>: CanonicalSerialize,
        Challenge<C>: CanonicalSerialize,
        ParticipantIdentifier<C>: Serialize,
        C::Participant: Serialize,
    {
        let path = format!("log_{}", coordinator.num_contributions());
        let mut writer = Vec::new();
        bincode::serialize_into(&mut writer, &coordinator.num_contributions)
            .expect("Serialize should succeed");
        let proof = coordinator
            .proof
            .clone()
            .expect("Coordinator should have non-empty proof.");
        proof[0]
            .serialize(&mut writer)
            .expect("Serialize should succeed");
        proof[1]
            .serialize(&mut writer)
            .expect("Serialize should succeed");
        proof[2]
            .serialize(&mut writer)
            .expect("Serialize should succeed");
        bincode::serialize_into(&mut writer, &coordinator.latest_contributor)
            .expect("Serialize should succeed.");
        let state = coordinator.state.clone();
        state[0]
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        state[1]
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        state[2]
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        let challenge = coordinator.challenge.clone();
        challenge[0]
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        challenge[1]
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        challenge[2]
            .serialize(&mut writer)
            .expect("Serialize should succeed.");
        bincode::serialize_into(&mut writer, &coordinator.registry)
            .expect("Serialize should succeed.");
        let mut file = File::create(log_dir.as_ref().join(&path)).expect("Unable to create file.");
        file.write_all(&writer).expect("Unable to write to file.");
        file.flush().expect("Unable to flush file.");
        info!("Saved coordinator to {}", path);
    }

    /// Recovers from a disk file.
    #[inline]
    pub fn recover_from_file(recovery_file_path: String, recovery_dir_path: String) -> Self
    where
        Proof<C>: CanonicalDeserialize,
        State<C>: CanonicalDeserialize,
        Challenge<C>: CanonicalDeserialize,
        ParticipantIdentifier<C>: DeserializeOwned,
        C::Participant: DeserializeOwned,
    {
        // cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir . --recovery log_1 recover
        let mut file = File::open(recovery_file_path).expect("Unable to open file.");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("Unable to read file.");
        let mut reader = &buf[..];
        let num_contributions =
            bincode::deserialize_from(&mut reader).expect("Deserialize should succeed.");
        let proof0: Proof<C> =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let proof1: Proof<C> =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let proof2: Proof<C> =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let proof = [proof0, proof1, proof2];
        let latest_contributor =
            bincode::deserialize_from(&mut reader).expect("Deserialize should succeed.");
        let state0 =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let state1 =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let state2 =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let challenge0 =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let challenge1 =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let challenge2 =
            CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
        let registry = bincode::deserialize_from(&mut reader).expect("Deserialize should succeed.");
        Self {
            coordinator: Arc::new(Mutex::new(Coordinator::new(
                num_contributions,
                Some(proof),
                latest_contributor,
                [state0, state1, state2],
                [challenge0, challenge1, challenge2],
                registry,
            ))),
            recovery_path: recovery_dir_path,
        }
    }

    /// Executes `f` on the incoming `request`.
    #[inline]
    pub async fn execute<T, R, F, Fut>(
        mut request: Request<Self>,
        f: F,
    ) -> Result<Response, tide::Error>
    where
        T: DeserializeOwned,
        R: Serialize,
        F: FnOnce(Self, T) -> Fut,
        Fut: Future<Output = Result<R, CeremonyError<C>>>,
    {
        into_body::<C, _, _, _>(move || async move {
            f(
                request.state().clone(),
                request
                    .body_json::<T>()
                    .await
                    .expect("Read and deserialize should succeed."),
            )
            .await
        })
        .await
    }
}

/// Generates the JSON body for the output of `f`, returning an HTTP reponse.
#[inline]
pub async fn into_body<C, R, F, Fut>(f: F) -> Result<Response, tide::Error>
where
    C: CeremonyConfig,
    R: Serialize,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R, CeremonyError<C>>>,
{
    let result = f().await;
    Ok(Body::from_json(&result)?.into())
}
