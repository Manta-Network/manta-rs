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

use crate::{
    ceremony::{
        coordinator::Coordinator,
        message::{
            ContributeRequest, QueryMPCStateRequest, QueryMPCStateResponse, RegisterRequest, Signed,
        },
        queue::{Identifier, Priority},
        registry::Map,
        signature,
        signature::SignatureScheme,
        CeremonyError,
    },
    mpc,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    future::Future,
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use tide::{Body, Request, Response};

/// Has Nonce
pub trait HasNonce<S>
where
    S: SignatureScheme,
{
    /// Returns the nonce of `self` as a participant.
    fn nonce(&self) -> S::Nonce;

    /// Updates the nonce of `self` as a participant.
    ///
    /// # Error
    ///
    /// Returns `CeremonyError::InvalidNonce` if the nonce is smaller or equal to previous nonce.
    fn update_nonce(&mut self, nonce: S::Nonce) -> Result<(), CeremonyError>;
}

/// Server with `V` as trusted setup verifier, `P` as participant, `M` as the map used by registry, `N` as the number of priority levels.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Server<V, P, M, S, const N: usize>
where
    S: SignatureScheme,
    V: mpc::Verify,
    P: Priority + Identifier + signature::HasPublicKey<PublicKey = S::PublicKey> + HasNonce<S>,
    M: Map<Key = P::Identifier, Value = P>,
{
    /// Coordinator
    coordinator: Arc<Mutex<Coordinator<V, P, M, N>>>,

    /// Type Parameter Marker
    __: PhantomData<S>,
}

// TODO: The implementation is currently not generic over S: SignatureScheme
impl<V, P, M, S, const N: usize> Server<V, P, M, S, N>
where
    V: mpc::Verify,
    S: SignatureScheme,
    P: Clone
        + Priority
        + Identifier
        + signature::HasPublicKey<PublicKey = S::PublicKey>
        + HasNonce<S>,
    M: Map<Key = P::Identifier, Value = P>,
{
    /// Verifies the registration request and registers a participant.
    #[inline]
    pub async fn register_participant(
        self,
        request: Signed<RegisterRequest<P>, S::Signature>,
    ) -> Result<(), CeremonyError>
    where
        RegisterRequest<P>: Serialize,
    {
        let (request, signature) = (request.message, request.signature);
        S::verify(
            &request,
            &request.participant.nonce(),
            &signature,
            &request.participant.public_key(),
        )
        .expect("Verify register request should succeed.");
        self.coordinator
            .lock()
            .expect("Failed to lock coordinator")
            .register(request.participant)
    }

    /// Gets MPC States and Challenge
    #[inline]
    pub async fn get_state_and_challenge(
        self,
        request: Signed<QueryMPCStateRequest<P>, S::Signature>,
    ) -> Result<QueryMPCStateResponse<V>, CeremonyError>
    where
        QueryMPCStateRequest<P>: Serialize,
    {
        let (request, signature) = (request.message, request.signature);
        S::verify(
            &request,
            &request.participant.nonce(),
            &signature,
            &request.participant.public_key(),
        )
        .expect("Verify signature of query MPC state should succeed.");
        let state = self.coordinator.lock().expect("Failed to lock coordinator");
        if state.is_next(&request.participant) {
            let (state, challenge) = state.state_and_challenge();
            Ok(QueryMPCStateResponse::Mpc(state.clone(), challenge.clone())) // TODO: remove this clone later
        } else {
            match state.position(&request.participant) {
                Some(position) => Ok(QueryMPCStateResponse::QueuePosition(position)),
                None => Err(CeremonyError::NotRegistered),
            }
        }
    }

    /// Processes a request to update the MPC state and remove the participant if successfully updated the state.
    #[inline]
    pub async fn update(
        self,
        request: Signed<ContributeRequest<P, V>, S::Signature>,
    ) -> Result<(), CeremonyError>
    where
        ContributeRequest<P, V>: Serialize,
        V::State: Default,
    {
        let (request, signature) = (request.message, request.signature);
        S::verify(
            &request,
            &request.participant.nonce(),
            &signature,
            &request.participant.public_key(),
        )
        .expect("Verify signature of contribute request should succeed.");
        self.coordinator
            .lock()
            .expect("Lock coordinator should succeed.")
            .update(
                &request.participant.identifier(),
                request.state,
                request.proof,
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
        Fut: Future<Output = Result<R, CeremonyError>>,
    {
        into_body(move || async move {
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
pub async fn into_body<R, F, Fut>(f: F) -> Result<Response, tide::Error>
where
    R: Serialize,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R, CeremonyError>>,
{
    Ok(Body::from_json(&f().await.map_err(tide::Error::from_display)?)?.into())
}
