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

use super::{
    message::ServerSize,
    participant::HasContributed,
    signature::{ed_dalek::Ed25519, verify},
};
use crate::{
    ceremony::{
        config::{CeremonyConfig, Challenge, Nonce, ParticipantIdentifier, Proof, State},
        coordinator::Coordinator,
        message::{CeremonyError, ContributeRequest, QueryRequest, QueryResponse, Signed},
        registry::Registry,
        signature::{check_nonce, HasNonce, HasPublicKey, Nonce as _, SignatureScheme},
        util::{load_from_file, log_to_file},
    },
    util::AsBytes,
};
use alloc::sync::Arc;
use core::{fmt::Debug, future::Future, ops::Deref};
use manta_crypto::{
    arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize},
    signature::Verify,
};
use manta_util::{
    http::tide::{self, Body, Request, Response},
    serde::{de::DeserializeOwned, Serialize},
    Array,
};
use parking_lot::Mutex;
use std::path::Path;

/// Server
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Server<C, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
where
    C: CeremonyConfig,
{
    /// Coordinator
    coordinator: Arc<Mutex<Coordinator<C, LEVEL_COUNT, CIRCUIT_COUNT>>>,

    /// Recovery Directory Path
    recovery_path: String,
}

impl<C, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize> Server<C, LEVEL_COUNT, CIRCUIT_COUNT>
where
    C: CeremonyConfig,
{
    /// Builds a [`Server`] with initial `state`, `challenge`, a loaded `registry`, and a `recovery_path`.
    #[inline]
    pub fn new(
        state: Array<AsBytes<State<C>>, CIRCUIT_COUNT>,
        challenge: Array<AsBytes<Challenge<C>>, CIRCUIT_COUNT>,
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
        registry: &mut Registry<ParticipantIdentifier<C>, C::Participant>,
        request: &Signed<T, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        T: Serialize,
    {
        let participant = match registry.get_mut(&request.identifier) {
            Some(participant) => {
                if participant.has_contributed() {
                    return Err(CeremonyError::AlreadyContributed);
                }
                participant
            }
            None => return Err(CeremonyError::NotRegistered),
        };
        let participant_nonce = participant.nonce();
        if !check_nonce(&participant_nonce, &request.nonce) {
            return Err(CeremonyError::NonceNotInSync(participant_nonce));
        }
        verify::<_, C::SignatureScheme>(
            &request.message,
            request.nonce.clone(),
            &participant.public_key(),
            &request.signature,
        )
        .map_err(|_| CeremonyError::BadRequest)?;
        participant.set_nonce(participant_nonce.increment());
        Ok(())
    }

    /// Gets the server state size and the current nonce of the participant.
    #[inline]
    pub async fn start(
        self,
        request: ParticipantIdentifier<C>,
    ) -> Result<(ServerSize, Nonce<C>), CeremonyError<C>> {
        let coordinator = self.coordinator.lock();
        Ok((
            coordinator.size.clone(),
            coordinator
                .get_participant(&request)
                .ok_or(CeremonyError::NotRegistered)?
                .nonce(),
        ))
    }

    /// Queries the server state.
    #[inline]
    pub async fn query(
        self,
        request: Signed<QueryRequest, C>,
    ) -> Result<QueryResponse<C, CIRCUIT_COUNT>, CeremonyError<C>>
    where
        ParticipantIdentifier<C>: Serialize,
        State<C>: CanonicalSerialize + CanonicalDeserialize,
        Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
    {
        let mut coordinator = self.coordinator.lock();
        Self::preprocess_request(&mut coordinator.registry, &request)?;
        if !coordinator.is_in_queue(&request.identifier)? {
            coordinator.enqueue_participant(&request.identifier)?;
        }
        if coordinator.is_next(&request.identifier) {
            Ok(QueryResponse::Mpc(coordinator.state_and_challenge()))
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
        request: Signed<ContributeRequest<C, CIRCUIT_COUNT>, C>,
    ) -> Result<(), CeremonyError<C>>
    where
        C::Participant: Serialize,
        State<C>: Debug + CanonicalDeserialize + CanonicalSerialize,
        Proof<C>: Debug + CanonicalDeserialize + CanonicalSerialize,
        ParticipantIdentifier<C>: Serialize,
        Challenge<C>: CanonicalSerialize + CanonicalDeserialize,
    {
        let mut coordinator = self.coordinator.lock();
        Self::preprocess_request(&mut coordinator.registry, &request)?;
        let contribute_state = request.message.contribute_state;
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
        log_to_file(
            &Path::new(&self.recovery_path)
                .join(format!("transcript{}.data", coordinator.num_contributions)),
            &coordinator.deref(),
        );
        println!(
            "{} participants have contributed.",
            coordinator.num_contributions
        );
        Ok(())
    }

    //     /// Executes `f` on the incoming `request`.
    //     #[inline]
    //     pub async fn execute<T, R, F, Fut>(
    //         mut request: Request<Self>,
    //         f: F,
    //     ) -> Result<Response, tide::Error>
    //     where
    //         T: DeserializeOwned,
    //         R: Serialize,
    //         F: FnOnce(Self, T) -> Fut,
    //         Fut: Future<Output = Result<R, CeremonyError<C>>>,
    //     {
    //         into_body::<C, _, _, _>(move || async move {
    //             f(
    //                 request.state().clone(),
    //                 request
    //                     .body_json::<T>()
    //                     .await
    //                     .expect("Read and deserialize should succeed."),
    //             )
    //             .await
    //         })
    //         .await
    //     }

    //     /// Recovers from a disk file at `recovery` and use `backup` as the backup directory.
    //     #[inline]
    //     pub fn recover(recovery: String, backup: String) -> Self
    //     where
    //         Proof<C>: CanonicalDeserialize + Debug,
    //         State<C>: CanonicalDeserialize + Debug,
    //         Challenge<C>: CanonicalDeserialize + Debug,
    //         ParticipantIdentifier<C>: CanonicalDeserialize,
    //         C::Participant: CanonicalDeserialize,
    //     {
    //         Self {
    //             coordinator: Arc::new(Mutex::new(load_from_file(recovery))),
    //             recovery_path: backup,
    //         }
    //     }
}

// /// Generates the JSON body for the output of `f`, returning an HTTP reponse.
// #[inline]
// pub async fn into_body<C, R, F, Fut>(f: F) -> Result<Response, tide::Error>
// where
//     C: CeremonyConfig,
//     R: Serialize,
//     F: FnOnce() -> Fut,
//     Fut: Future<Output = Result<R, CeremonyError<C>>>,
// {
//     let result = f().await;
//     Ok(Body::from_json(&result)?.into())
// }

// /// Initiates a server.
// #[inline]
// pub fn init_server(registry_path: String, recovery_dir_path: String) -> Server<Groth16BLS12381, 2> {
//     let registry = load_registry::<Groth16BLS12381, _>(registry_path);
//     let mpc_state0 = load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_mint.data");
//     let mpc_state1 =
//         load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_private_transfer.data");
//     let mpc_state2 =
//         load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_reclaim.data");
//     let size = ServerSize {
//         mint: StateSize {
//             gamma_abc_g1: mpc_state0.state[0].vk.gamma_abc_g1.len(),
//             a_b_g1_b_g2_query: mpc_state0.state[0].a_query.len(),
//             h_query: mpc_state0.state[0].h_query.len(),
//             l_query: mpc_state0.state[0].l_query.len(),
//         },
//         private_transfer: StateSize {
//             gamma_abc_g1: mpc_state1.state[0].vk.gamma_abc_g1.len(),
//             a_b_g1_b_g2_query: mpc_state1.state[0].a_query.len(),
//             h_query: mpc_state1.state[0].h_query.len(),
//             l_query: mpc_state1.state[0].l_query.len(),
//         },
//         reclaim: StateSize {
//             gamma_abc_g1: mpc_state2.state[0].vk.gamma_abc_g1.len(),
//             a_b_g1_b_g2_query: mpc_state2.state[0].a_query.len(),
//             h_query: mpc_state2.state[0].h_query.len(),
//             l_query: mpc_state2.state[0].l_query.len(),
//         },
//     };
//     Server::<Groth16BLS12381, 2>::new(
//         [
//             mpc_state0.state[0].clone(),
//             mpc_state1.state[0].clone(),
//             mpc_state2.state[0].clone(),
//         ],
//         [
//             mpc_state0.challenge[0],
//             mpc_state1.challenge[0],
//             mpc_state2.challenge[0],
//         ],
//         registry,
//         recovery_dir_path,
//         size,
//     )
// }
