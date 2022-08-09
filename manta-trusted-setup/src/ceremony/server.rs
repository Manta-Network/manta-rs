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

//! Asynchronous server for trusted setup.

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

/// Server with `V` as trusted setup verifier, `P` as participant, `M` as the map used by registry, `N` as the number of priority levels.
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
    pub coordinator: Arc<Mutex<Coordinator<C, N>>>, // TODO: Make this private
}

impl<C, const N: usize> Server<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize + CanonicalDeserialize,
    Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
    Proof<C>: CanonicalSerialize + CanonicalDeserialize,
{
    /// Initialize a server with initial state and challenge.
    pub fn new(
        state: State<C>,
        challenge: Challenge<C>,
        registry: Registry<ParticipantIdentifier<C>, C::Participant>,
    ) -> Self {
        Self {
            coordinator: Arc::new(Mutex::new(Coordinator::new(state, challenge, registry))),
        }
    }

    /// Verifies the registration request and registers a participant.
    #[inline]
    pub async fn enqueue_participant(
        self,
        request: Signed<EnqueueRequest<C>, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
    {
        let mut coordinator = self.coordinator.lock().unwrap();
        let participant = match coordinator.get_participant(&request.message.identifier) {
            Some(participant) => participant,
            None => return Err(CeremonyError::NotRegistered),
        };
        if participant.nonce() != request.nonce {
            return Err(CeremonyError::NonceNotInSync(participant.nonce()));
        }
        C::SignatureScheme::verify(
            &request.message.identifier,
            &request.nonce,
            &request.signature,
            &participant.public_key(),
        )
        .map_err(|_| CeremonyError::BadRequest)?; // TODO
        let identifier = participant.identifier();
        coordinator.enqueue_participant(&identifier)
    }

    /// Gets MPC States and Challenge
    #[inline]
    pub async fn get_state_and_challenge(
        self,
        request: Signed<QueryMPCStateRequest<C>, C>,
    ) -> Result<QueryMPCStateResponse<C>, CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
    {
        // TODO: duplicate code
        let coordinator = self.coordinator.lock().unwrap();
        let participant = match coordinator.get_participant(&request.message.identifier) {
            Some(participant) => participant,
            None => return Err(CeremonyError::NotRegistered),
        };
        if participant.nonce() != request.nonce {
            return Err(CeremonyError::NonceNotInSync(participant.nonce()));
        }
        C::SignatureScheme::verify(
            &request.message.identifier,
            &participant.nonce(),
            &request.signature,
            &participant.public_key(),
        )
        .expect("Verify signature of query MPC state should succeed.");
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
    {
        // TODO: duplicate code
        let mut coordinator = self.coordinator.lock().unwrap();
        let participant = match coordinator.get_participant(&request.message.identifier) {
            Some(participant) => participant,
            None => return Err(CeremonyError::NotRegistered),
        };
        if participant.nonce() != request.nonce {
            return Err(CeremonyError::NonceNotInSync(participant.nonce()));
        }
        C::SignatureScheme::verify(
            &request.message,
            &participant.nonce(),
            &request.signature,
            &participant.public_key(),
        )
        .map_err(|_| CeremonyError::BadRequest)?; // TODO
        let identifier = participant.identifier();
        coordinator.update(
            &identifier,
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
