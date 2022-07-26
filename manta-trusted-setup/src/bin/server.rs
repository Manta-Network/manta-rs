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
//! Waiting queue for the ceremony.

use core::{future::Future, marker::PhantomData};
use manta_trusted_setup::{
    ceremony::{
        coordinator::*,
        queue::*,
        registry::Map,
        requests::*,
        signature,
        signature::{ed_dalek_signatures::*, SignatureScheme},
        CeremonyError,
    },
    mpc,
};
use parking_lot::Mutex;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tide::{Body, Request, Response, StatusCode};
// use manta_trusted_setup::ceremony::CeremonyError;

#[derive(Clone)]
/// Server with `V` as trusted setup verifier, `P` as participant, `M` as the map used by registry, `N` as the number of priority levels.
pub struct Server<V, P, M, S, const N: usize>(Arc<Mutex<Coordinator<V, P, M, S, N>>>)
where
    V: mpc::Verify,
    P: Priority + Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    M: Map<Key = P::Identifier, Value = P>,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>;

impl<V, P, M, S, const N: usize> Server<V, P, M, S, N>
where
    V: mpc::Verify,
    P: Priority + Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    M: Map<Key = P::Identifier, Value = P>,
    V::State: Default + signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    /// Registers then queues a participant // TODO The registration is by hand, so queueing should be split from it
    #[inline]
    async fn register_participant<'a>(self, request: RegisterRequest<P>) -> Result<()> {
        let mut state = self.0.lock();
        state.register(request.participant).map_err(Error::from)
    }

    /// Adds a participant to the queue if they are registered. Todo: join queue should return position
    #[inline]
    async fn join_queue(self, request: JoinQueueRequest<P, S>) -> Result<usize> {
        let mut state = self.0.lock();
        todo!()
    }

    /// Gives current MPC state and challenge if participant is at front of queue.
    #[inline]
    async fn get_state_and_challenge(
        self,
        request: GetMpcRequest<P, S, V>,
    ) -> Result<GetMpcResponse<S, V>> {
        let state = self.0.lock();

        if state.is_next(&request.participant) {
            println!("Served state to next participant");
            Ok(GetMpcResponse::default()) // this is the variant with the state
        } else {
            println!("Told participant to wait their turn.");
            Ok(GetMpcResponse::default()) // this is the variant with queue position
        }
    }

    /// Processes a request to update the MPC state. If successful then participant is removed from queue.
    #[inline]
    async fn update(self, request: ContributeRequest<P, S, V>) -> Result<()> {
        let mut state = self.0.lock();
        state
            .update(
                &request.participant.identifier(),
                request.transformed_state,
                request.proof,
                &request.sig,
            )
            .map_err(Error::from)
    }

    // /// Executes `f` on the incoming `request`.
    // #[inline]
    // async fn execute<T, R, F, Fut>(
    //     mut request: Request<Self>, // get json from here
    //     f: F,
    // ) -> Result<Response, tide::Error>
    // where
    //     T: DeserializeOwned, // Request type that would have been received from Client
    //     R: Serialize,        // Response
    //     F: FnOnce(Self, T) -> Fut, // endpoint must be of this form
    //     Fut: Future<Output = Result<R>>, // R is the type returned by Server, like Attestation
    // {
    //     let args = request.body_json::<T>().await?; // parse json into its args
    //     into_body(move || async move {
    //         f(request.state().clone(), args).await // pass those args to f, as well as a copy of the State -- rather ArcMutex<State>, hence clonable
    //     })
    //     .await
    // }
}

fn main() {}

pub enum Error {
    AlreadyQueued,
    InvalidSignature,
    CeremonyError(CeremonyError),
} // all server errors go into this enum

impl From<Error> for tide::Error {
    #[inline]
    fn from(err: Error) -> tide::Error {
        match err {
            _ => Self::from_str(
                StatusCode::InternalServerError,
                "unable to complete request",
            ),
        }
    }
}

impl From<CeremonyError> for Error {
    #[inline]
    fn from(e: CeremonyError) -> Self {
        Self::CeremonyError(e)
    }
}

// Result Type
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Generates the JSON body for the output of `f`, returning an HTTP reponse.
#[inline]
async fn into_body<R, F, Fut>(f: F) -> Result<Response, tide::Error>
where
    R: Serialize,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R>>,
{
    Ok(Body::from_json(&f().await?)?.into())
}
