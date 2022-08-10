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

use crate::ceremony::{
    config::{CeremonyConfig, Challenge, ParticipantIdentifier, Proof, State},
    coordinator::Coordinator,
    message::{
        ContributeRequest, EnqueueRequest, QueryMPCStateRequest, QueryMPCStateResponse, Signed,
    },
    queue::Identifier,
    registry::Registry,
    signature::{HasPublicKey, SignatureScheme},
    CeremonyError,
};
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tide::{Body, Request, Response, StatusCode};

/// Has Nonce
pub trait HasNonce<S>
where
    S: SignatureScheme,
{
    /// Returns the nonce of `self` as a participant.
    fn nonce(&self) -> S::Nonce;

    /// TODO: since we only increase nonce by 1 for each time, we can have this helper function
    /// so we do not additionally require traits on nonce such as it can be increased by
    /// a u64 number of usize number.
    fn update_nonce(&mut self);
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
    coordinator: Arc<Mutex<Coordinator<C, N>>>,
}

impl<C, const N: usize> Server<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize + CanonicalDeserialize,
    Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
    Proof<C>: CanonicalSerialize + CanonicalDeserialize,
{
    /// Builds a [`Server`] with initial `state`, `challenge`, and a loaded `registry`.
    pub fn new(
        state: State<C>,
        challenge: Challenge<C>,
        registry: Registry<ParticipantIdentifier<C>, C::Participant>,
    ) -> Self {
        Self {
            coordinator: Arc::new(Mutex::new(Coordinator::new(state, challenge, registry))),
        }
    }

    /// Preprocessed a request by checking nonce and verifying signature.
    #[inline]
    pub fn preprocess_request<T>(&self, request: &Signed<T, C>) -> Result<(), CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
    {
        let coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        let participant = match coordinator.get_participant(&request.identifier) {
            Some(participant) => participant,
            None => return Err(CeremonyError::NotRegistered), // TODO: Not sure if this Err(...) will be sent back to client binary.
        };
        if participant.nonce() != request.nonce {
            return Err(CeremonyError::NonceNotInSync(participant.nonce()));
        }
        C::SignatureScheme::verify(
            &request.identifier,
            &request.nonce,
            &request.signature,
            &participant.public_key(),
        )
        .map_err(|_| CeremonyError::BadRequest)?; // TODO
        Ok(())
    }

    /// Verifies the enqueue request and enqueues a participant.
    #[inline]
    pub async fn enqueue_participant(
        self,
        request: Signed<EnqueueRequest, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
    {
        self.preprocess_request(&request)?;
        let mut coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        coordinator.enqueue_participant(&request.identifier)?;
        Ok(())
    }

    /// Gets MPC States and Challenge
    #[inline]
    pub async fn get_state_and_challenge(
        self,
        request: Signed<QueryMPCStateRequest, C>,
    ) -> Result<QueryMPCStateResponse<C>, CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
    {
        // TODO: duplicate code
        self.preprocess_request(&request)?;
        let coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        let participant = match coordinator.get_participant(&request.identifier) {
            Some(participant) => participant,
            None => return Err(CeremonyError::NotRegistered), // TODO: Not sure if this Err(...) will be sent back to client binary.
        };
        if coordinator.is_next(&participant) {
            let (state, challenge) = coordinator.state_and_challenge();
            println!("get_state_and_challenge. Will respond.");
            Ok(QueryMPCStateResponse::Mpc(
                state.clone().into(),
                challenge.clone().into(),
            )) // TODO: remove this clone later
        } else {
            match coordinator.position(&participant) {
                Some(position) => {
                    // println!("Need to wait more time.");
                    Ok(QueryMPCStateResponse::QueuePosition(position))
                }
                None => {
                    unreachable!("Participant should be always in the queue here")
                }
            }
        }
    }

    /// Processes a request to update the MPC state and remove the participant if successfully updated the state.
    #[inline]
    pub async fn update(
        self,
        request: Signed<ContributeRequest<C>, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        ContributeRequest<C>: Serialize,
        ParticipantIdentifier<C>: Serialize,
    {
        self.preprocess_request(&request)?;
        let mut coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        coordinator.update(
            &request.identifier,
            request
                .message
                .state
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
            request
                .message
                .proof
                .to_actual()
                .map_err(|_| CeremonyError::BadRequest)?,
        )
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

    if matches!(&result, Err(CeremonyError::<C>::BadRequest)) {
        return Err(tide::Error::from_str(StatusCode::BadRequest, "Bad Request"));
    }

    Ok(Body::from_json(&result)?.into())
}
