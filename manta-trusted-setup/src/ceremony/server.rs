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
    config::{CeremonyConfig, Challenge, Nonce, ParticipantIdentifier, Proof, State},
    coordinator::Coordinator,
    message::{
        ContributeRequest, EnqueueRequest, QueryMPCStateRequest, QueryMPCStateResponse, Signed,
    },
    registry::Registry,
    signature::{HasPublicKey, Nonce as _, SignatureScheme},
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

    /// Set nonce
    fn set_nonce(&mut self, nonce: S::Nonce);
}

/// Has Contributed
pub trait HasContributed {
    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets the participant as contributed.
    fn set_contributed(&mut self);
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

    /// Preprocesses a request by checking nonce and verifying signature.
    #[inline]
    pub fn preprocess_request<T>(
        &self,
        coordinator: &mut Coordinator<C, N>,
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

    /// Verifies the enqueue request and enqueues a participant.
    #[inline]
    pub async fn enqueue_participant(
        self,
        request: Signed<EnqueueRequest, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
    {
        let mut coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        self.preprocess_request(&mut *coordinator, &request)?;
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
        let mut coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        self.preprocess_request(&mut *coordinator, &request)?;
        let participant = coordinator
            .get_participant(&request.identifier)
            .expect("Participant existence is checked in `process_request`.");
        if coordinator.is_next(&request.identifier) {
            let (state, challenge) = coordinator.state_and_challenge();
            Ok(QueryMPCStateResponse::Mpc(
                state.clone().into(),
                challenge.clone().into(),
            )) // TODO: remove this clone later
        } else {
            match coordinator.position(&participant) {
                Some(position) => Ok(QueryMPCStateResponse::QueuePosition(position)),
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
        let mut coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        println!("Enter update.");
        self.preprocess_request(&mut *coordinator, &request)?;
        println!("In update, preprocessed request.");
        match coordinator.get_participant(&request.identifier) {
            Some(participant) => {
                if participant.has_contributed() {
                    println!("In update, participant has contributed.");
                    return Err(CeremonyError::<C>::BadRequest); // TODO. Should tell client that you have contributed successfully before.
                }
            }
            None => {
                println!("In update, participant does not exist in registry.");
                return Err(CeremonyError::<C>::BadRequest); // TODO
            }
        }
        println!("After get participant.");
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
        )?; // TODO: What would happen if the server goes down after this update and before `set_contributed`?
        println!("Update successfully!");
        coordinator
            .get_participant_mut(&request.identifier)
            .expect("Geting participant should succeed.")
            .set_contributed();
        println!("Set the contributor as contributed!");
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
        let coordinator = self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.");
        let participant = coordinator
            .get_participant(&request)
            .ok_or(CeremonyError::NotRegistered)?;
        Ok(participant.nonce())
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
