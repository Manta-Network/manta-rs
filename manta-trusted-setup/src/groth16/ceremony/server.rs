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

use crate::groth16::{
    ceremony::{
        coordinator::Coordinator,
        message::{CeremonySize, ContributeRequest, QueryRequest, QueryResponse, Signed},
        participant::{Participant, Priority},
        registry::Registry,
        signature::{verify, Message},
        util::{deserialize_from_file, serialize_into_file},
        Ceremony, CeremonyError, Participant as _,
    },
    mpc::{State, StateSize},
};
use alloc::sync::Arc;
use core::{convert::TryInto, ops::Deref};
use manta_crypto::{
    dalek::ed25519::{self, Ed25519},
    rand::{OsRng, Rand},
};
use manta_util::{
    serde::{de::DeserializeOwned, Serialize},
    BoxArray,
};
use parking_lot::Mutex;
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

/// Server
pub struct Server<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Coordinator
    coordinator: Arc<Mutex<Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>>>,

    /// Recovery directory path
    recovery_path: String,
}

impl<C, R, const LEVEL_COUNT: usize, const CIRCUIT_COUNT: usize>
    Server<C, R, LEVEL_COUNT, CIRCUIT_COUNT>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
{
    /// Builds a ['Server`] with initial `state`, `challenge`, a loaded `registry`, and a `recovery_path`.
    #[inline]
    pub fn new(
        state: BoxArray<State<C>, CIRCUIT_COUNT>,
        challenge: BoxArray<C::Challenge, CIRCUIT_COUNT>,
        registry: R,
        recovery_path: String,
        size: BoxArray<StateSize, CIRCUIT_COUNT>,
    ) -> Self {
        let coordinator = Coordinator::new(registry, state, challenge, size);
        Self {
            coordinator: Arc::new(Mutex::new(coordinator)),
            recovery_path,
        }
    }

    /// Gets the server state size and the current nonce of the participant.
    #[inline]
    pub async fn start(
        self,
        request: C::Identifier,
    ) -> Result<(CeremonySize<CIRCUIT_COUNT>, C::Nonce), CeremonyError<C>> {
        let coordinator = self.coordinator.lock();
        Ok((
            CeremonySize(BoxArray::from_unchecked(*coordinator.size())),
            coordinator
                .registry()
                .get(&request)
                .ok_or(CeremonyError::NotRegistered)?
                .nonce(),
        ))
    }

    /// Queries the server state
    #[inline]
    pub async fn query(
        self,
        request: Signed<QueryRequest, C>,
    ) -> Result<QueryResponse<C, CIRCUIT_COUNT>, CeremonyError<C>>
    where
        C::Challenge: Clone,
    {
        let mut coordinator = self.coordinator.lock();
        let priority = coordinator.preprocess_request(&request)?;
        let position = coordinator
            .queue_mut()
            .push_back_if_missing(priority.into(), request.identifier);
        if position == 0 {
            Ok(QueryResponse::Mpc(coordinator.state_and_challenge()))
        } else {
            Ok(QueryResponse::QueuePosition(position))
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
        Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>: Serialize,
    {
        let mut coordinator = self.coordinator.lock();
        coordinator.preprocess_request(&request)?;
        let message = request.message;
        coordinator.update(&request.identifier, message.state, message.proof)?;
        serialize_into_file(
            OpenOptions::new().write(true).create_new(true),
            &Path::new(&self.recovery_path).join(format!("transcript{}.data", coordinator.round())),
            &coordinator.deref(),
        )
        .map_err(|_| CeremonyError::Unexpected)?;
        println!("{} participants have contributed.", coordinator.round());
        Ok(())
    }
}

/// Recovers from a disk file at `recovery` and use `recovery_path` as the backup directory.
#[inline]
pub fn recover<C, R, const CIRCUIT_COUNT: usize, const LEVEL_COUNT: usize>(
    recovery: String,
    recovery_path: String,
) -> Result<Server<C, R, LEVEL_COUNT, CIRCUIT_COUNT>, CeremonyError<C>>
where
    C: Ceremony,
    R: Registry<C::Identifier, C::Participant>,
    Coordinator<C, R, CIRCUIT_COUNT, LEVEL_COUNT>: DeserializeOwned,
{
    Ok(Server {
        coordinator: Arc::new(Mutex::new(
            deserialize_from_file(recovery).map_err(|_| CeremonyError::Unexpected)?,
        )),
        recovery_path,
    })
}

/// Loads registry from a disk file at `registry`.
#[inline]
pub fn load_registry<C, P, R>(registry_file: P) -> R
where
    C: Ceremony<Nonce = u64, Participant = Participant<C>, VerifyingKey = ed25519::PublicKey>,
    P: AsRef<Path>,
    R: Registry<C::VerifyingKey, C::Participant>,
{
    let mut registry = R::new();
    for record in
        csv::Reader::from_reader(File::open(registry_file).expect("Registry file should exist."))
            .records()
    {
        let result = record.expect("Read csv should succeed.");
        let twitter = result[0].to_string();
        let email = result[1].to_string();
        let verifying_key: ed25519::PublicKey = ed25519::public_key_from_bytes(
            bs58::decode(result[3].to_string())
                .into_vec()
                .expect("Should convert into a vector")
                .try_into()
                .expect("Should give an array"),
        );
        let signature: ed25519::Signature = ed25519::signature_from_bytes(
            bs58::decode(result[4].to_string())
                .into_vec()
                .expect("Should convert into a vector")
                .try_into()
                .expect("Should give an array"),
        );
        verify::<_, Ed25519<Message<C::Nonce>>>(
            &verifying_key,
            0,
            &format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                twitter, email
            ),
            &signature,
        )
        .expect("Should verify the signature.");
        let participant: Participant<C> = Participant::new(
            verifying_key,
            twitter,
            match result[2].to_string().parse::<bool>().unwrap() {
                true => Priority::High,
                false => Priority::Normal,
            },
            OsRng.gen::<_, u16>() as u64,
            false,
        );
        registry.register(verifying_key, participant);
    }
    registry
}
