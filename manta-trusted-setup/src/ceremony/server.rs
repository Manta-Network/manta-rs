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
        config::{
            g16_bls12_381::Groth16BLS12381, CeremonyConfig, Challenge, Nonce,
            ParticipantIdentifier, Proof, State,
        },
        coordinator::Coordinator,
        message::{
            CeremonyError, ContributeRequest, QueryRequest, QueryResponse, Signed, SizeRequest,
        },
        registry::{load_registry, HasContributed, Registry},
        signature::{HasNonce, HasPublicKey, Nonce as _, SignatureScheme},
        state::{MPCState, ServerSize, StateSize},
        util::{load_from_file, log_to_file},
    },
    util::AsBytes,
};
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt::Debug,
    future::Future,
    ops::Deref,
    path::Path,
    sync::{Arc, Mutex},
};
use tide::{Body, Request, Response};

/// Server
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Server<C, const N: usize>
where
    C: CeremonyConfig,
{
    /// Coordinator
    coordinator: Arc<Mutex<Coordinator<C, N, 3>>>,

    /// Recovery Directory Path
    recovery_path: String,
}

impl<C, const N: usize> Server<C, N>
where
    C: CeremonyConfig,
{
    /// Builds a [`Server`] with initial `state`, `challenge`, a loaded `registry`, and a `recovery_path`.
    #[inline]
    pub fn new(
        state: [State<C>; 3],
        challenge: [Challenge<C>; 3],
        registry: Registry<ParticipantIdentifier<C>, C::Participant>,
        recovery_path: String,
        size: ServerSize,
    ) -> Self {
        Self {
            coordinator: Arc::new(Mutex::new(Coordinator::new(
                0, None, None, state, challenge, registry, size,
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

    /// Queries the server state size.
    #[inline]
    pub async fn get_state_size(self, _: SizeRequest) -> Result<ServerSize, CeremonyError<C>> {
        Ok(self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.")
            .size
            .clone())
    }

    /// Queries the server state.
    #[inline]
    pub async fn query(
        self,
        request: Signed<QueryRequest, C>,
    ) -> Result<QueryResponse<C>, CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
        State<C>: CanonicalSerialize + CanonicalDeserialize,
        Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
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
        request: Signed<ContributeRequest<C, 3>, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        C::Participant: CanonicalSerialize,
        State<C>: Debug + CanonicalDeserialize + CanonicalSerialize,
        Proof<C>: Debug + CanonicalDeserialize + CanonicalSerialize,
        ParticipantIdentifier<C>: CanonicalSerialize,
        Challenge<C>: CanonicalSerialize,
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
        let contribute_state = request
            .message
            .contribute_state
            .to_actual()
            .map_err(|_| CeremonyError::BadRequest)?;
        coordinator.update(
            &request.identifier,
            contribute_state.state,
            contribute_state.proof,
        )?;
        coordinator
            .get_participant_mut(&request.identifier)
            .expect("Geting participant should succeed.")
            .set_contributed();
        coordinator.num_contributions += 1;
        // TODO: checksum
        log_to_file(
            &Path::new(&self.recovery_path)
                .join(format!("log{}.data", coordinator.num_contributions)),
            coordinator.deref(),
        );
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
    ) -> Result<Nonce<C>, CeremonyError<C>> {
        Ok(self
            .coordinator
            .lock()
            .expect("Locking the coordinator should succeed.")
            .get_participant(&request)
            .ok_or(CeremonyError::NotRegistered)?
            .nonce())
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

    /// Recovers from a disk file at `recovery` and use `backup` as the backup directory.
    #[inline]
    pub fn recover(recovery: String, backup: String) -> Self
    where
        Proof<C>: CanonicalDeserialize + Debug,
        State<C>: CanonicalDeserialize + Debug,
        Challenge<C>: CanonicalDeserialize + Debug,
        ParticipantIdentifier<C>: CanonicalDeserialize,
        C::Participant: CanonicalDeserialize,
    {
        Self {
            coordinator: Arc::new(Mutex::new(load_from_file(recovery))),
            recovery_path: backup,
        }
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

/// Initiates a server.
pub fn init_server(registry_path: String, recovery_dir_path: String) -> Server<Groth16BLS12381, 2> {
    let registry = load_registry::<Groth16BLS12381, _>(registry_path);
    let mpc_state0 = load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_mint.data");
    let mpc_state1 =
        load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_private_transfer.data");
    let mpc_state2 =
        load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_reclaim.data");
    let size = ServerSize {
        mint: StateSize {
            gamma_abc_g1: mpc_state0.state[0].vk.gamma_abc_g1.len(),
            a_b_g1_b_g2_query: mpc_state0.state[0].a_query.len(),
            h_query: mpc_state0.state[0].h_query.len(),
            l_query: mpc_state0.state[0].l_query.len(),
        },
        private_transfer: StateSize {
            gamma_abc_g1: mpc_state1.state[0].vk.gamma_abc_g1.len(),
            a_b_g1_b_g2_query: mpc_state1.state[0].a_query.len(),
            h_query: mpc_state1.state[0].h_query.len(),
            l_query: mpc_state1.state[0].l_query.len(),
        },
        reclaim: StateSize {
            gamma_abc_g1: mpc_state2.state[0].vk.gamma_abc_g1.len(),
            a_b_g1_b_g2_query: mpc_state2.state[0].a_query.len(),
            h_query: mpc_state2.state[0].h_query.len(),
            l_query: mpc_state2.state[0].l_query.len(),
        },
    };
    Server::<Groth16BLS12381, 2>::new(
        [
            mpc_state0.state[0].clone(),
            mpc_state1.state[0].clone(),
            mpc_state2.state[0].clone(),
        ],
        [
            mpc_state0.challenge[0].clone(),
            mpc_state1.challenge[0].clone(),
            mpc_state2.challenge[0].clone(),
        ],
        registry,
        recovery_dir_path,
        size,
    )
}
