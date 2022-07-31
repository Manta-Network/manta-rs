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
//! Asyncronous server for trusted setup.

use crate::{
    ceremony::{
        coordinator::Coordinator,
        queue::{Identifier, Priority},
        registry::Map,
        requests::{ContributeRequest, GetMpcRequest, GetMpcResponse, RegisterRequest},
        signature,
        signature::{SignatureScheme, Signed},
        CeremonyError,
    },
    mpc,
};
use serde::de::DeserializeOwned;
use std::{
    future::Future,
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use tide::{prelude::*, Body, Request, Response};

/// Server with `V` as trusted setup verifier, `P` as participant, `M` as the map used by registry, `N` as the number of priority levels.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Server<V, P, M, S, const N: usize>
where
    V: mpc::Verify,
    P: Priority + Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    M: Map<Key = P::Identifier, Value = P>,
{
    coordinator: Arc<Mutex<Coordinator<V, P, M, N>>>,
    domain_tag: &'static S::DomainTag,
    __: PhantomData<S>,
}

// Note the implementation is currently not generic over S: SignatureScheme
impl<V, P, M, S, const N: usize> Server<V, P, M, S, N>
where
    V: mpc::Verify,
    P: Clone + Priority + Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    M: Map<Key = P::Identifier, Value = P>,
    V::State: Clone + signature::Verify<S>,
    V::Proof: Clone + signature::Verify<S>,
    P::PublicKey: signature::Verify<S>,
{
    /// Registers then queues a participant // TODO The registration is by hand, so queueing should be split from it
    #[inline]
    pub async fn register_participant<'a>(
        self,
        request: Signed<RegisterRequest<P>, S>,
    ) -> Result<(), CeremonyError>
    where
        Signed<RegisterRequest<P>, S>: Sized,
    {
        // Check signatures
        let public_key = request.message.participant.public_key();
        request.verify_integrity(self.domain_tag, &public_key)?;
        let mut state = self.coordinator.lock().expect("Failed to lock coordinator");
        state.register(request.message.participant)
    }

    /// Gives current MPC state and challenge if participant is at front of queue.
    #[inline]
    pub async fn get_state_and_challenge(
        self,
        request: Signed<GetMpcRequest<P, V>, S>,
    ) -> Result<GetMpcResponse<V>, CeremonyError>
    where
        Signed<GetMpcRequest<P, V>, S>: Sized,
    {
        // Check signatures
        let public_key = request.message.participant.public_key();
        request.verify_integrity(self.domain_tag, &public_key)?;

        let state = self.coordinator.lock().expect("Failed to lock coordinator");
        if state.is_next(&request.message.participant) {
            println!("Served state to next participant");
            Ok(GetMpcResponse::default()) // this is the variant with the state
        } else {
            println!("Told participant to wait their turn.");
            Ok(GetMpcResponse::default()) // this is the variant with queue position
        }
    }

    /// Processes a request to update the MPC state. If successful then participant is removed from queue.
    #[inline]
    pub async fn update(
        self,
        request: Signed<ContributeRequest<P, V>, S>,
    ) -> Result<(), CeremonyError>
    where
        Signed<ContributeRequest<P, V>, S>: Sized,
        V::State: Default,
    {
        // Check signatures
        let public_key = request.message.participant.public_key();
        request.verify_integrity(self.domain_tag, &public_key)?;

        let mut state = self.coordinator.lock().expect("Failed to lock coordinator");
        state.update(
            &request.message.participant.identifier(),
            request.message.transformed_state,
            request.message.proof,
        )
    }

    /// Executes `f` on the incoming `request`.
    #[inline]
    pub async fn execute<T, R, F, Fut>(
        mut request: Request<Self>, // get json from here
        f: F,
    ) -> Result<Response, tide::Error>
    where
        T: DeserializeOwned, // Request type that would have been received from Client
        R: Serialize,        // Response
        F: FnOnce(Self, T) -> Fut, // endpoint must be of this form
        Fut: Future<Output = Result<R, CeremonyError>>, // R is the type returned by Server, like Attestation
    {
        let args = request.body_json::<T>().await?; // parse json into its args
        into_body(move || async move {
            f(request.state().clone(), args).await // pass those args to f, as well as a copy of the State -- rather ArcMutex<State>, hence clonable
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
