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

//! Trusted Setup Client

use crate::{
    ceremony::signature::{Nonce, SignedMessage},
    groth16::{
        ceremony::{
            message::{CeremonySize, ContributeRequest, QueryRequest},
            Ceremony, CeremonyError,
        },
        mpc::{contribute, State},
    },
};
use console::style;
use core::fmt::Debug;
use manta_crypto::rand::OsRng;
use manta_util::{
    http::reqwest::KnownUrlClient,
    serde::{de::DeserializeOwned, Serialize},
    BoxArray,
};

/// Client
pub struct Client<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// Identifier
    identifier: C::Identifier,

    /// Current Nonce
    nonce: C::Nonce,

    /// Signing Key
    signing_key: C::SigningKey,
}

impl<C, const CIRCUIT_COUNT: usize> Client<C, CIRCUIT_COUNT>
where
    C: Ceremony,
{
    /// Builds a new [`Client`] with `participant` and `private_key`.
    #[inline]
    pub fn new(identifier: C::Identifier, nonce: C::Nonce, signing_key: C::SigningKey) -> Self {
        Self {
            identifier,
            nonce,
            signing_key,
        }
    }

    /// Queries the server state.
    #[inline]
    pub fn query(
        &mut self,
    ) -> Result<SignedMessage<C, C::Identifier, QueryRequest>, CeremonyError<C>> {
        let signed_message = SignedMessage::generate(
            &self.signing_key,
            self.nonce.clone(),
            self.identifier.clone(),
            QueryRequest,
        )
        .map_err(|_| {
            CeremonyError::Unexpected(
                "Cannot sign message since it cannot be serialized.".to_string(),
            )
        })?;
        self.nonce.increment();
        Ok(signed_message)
    }

    /// Contributes to the state on the server.
    #[inline]
    pub fn contribute(
        &mut self,
        hasher: &C::Hasher,
        challenge: &BoxArray<C::Challenge, CIRCUIT_COUNT>,
        mut state: BoxArray<State<C>, CIRCUIT_COUNT>,
    ) -> Result<
        SignedMessage<C, C::Identifier, ContributeRequest<C, CIRCUIT_COUNT>>,
        CeremonyError<C>,
    > {
        let circuit_name = ["ToPrivate", "PrivateTransfer", "ToPublic"];
        let mut rng = OsRng;
        let mut proofs = Vec::new();
        for i in 0..CIRCUIT_COUNT {
            println!(
                "{} Contributing to {} Circuits...",
                style(format!("[{}/9]", i + 5)).bold().dim(),
                circuit_name[i],
            );
            proofs.push(
                contribute(hasher, &challenge[i], &mut state[i], &mut rng)
                    .ok_or_else(|| CeremonyError::Unexpected("Cannot contribute.".to_string()))?,
            );
        }
        println!(
            "{} Waiting for Confirmation from Server... Estimated Waiting Time: {} minutes.",
            style("[8/9]").bold().dim(),
            style("3").bold().blue(),
        );
        let signed_message = SignedMessage::generate(
            &self.signing_key,
            self.nonce.clone(),
            self.identifier.clone(),
            ContributeRequest {
                state,
                proof: BoxArray::from_vec(proofs),
            },
        )
        .map_err(|_| {
            CeremonyError::Unexpected(
                "Cannot sign message since it cannot be serialized.".to_string(),
            )
        })?;
        self.nonce.increment();
        Ok(signed_message)
    }
}

/// Gets state size from server.
#[inline]
pub async fn get_start_meta_data<C, const CIRCUIT_COUNT: usize>(
    identity: C::Identifier,
    network_client: &KnownUrlClient,
) -> Result<(CeremonySize<CIRCUIT_COUNT>, C::Nonce), CeremonyError<C>>
where
    C: Ceremony,
    C::Identifier: Serialize,
    C::Nonce: DeserializeOwned + Debug,
{
    network_client
        .post::<_, Result<(CeremonySize<CIRCUIT_COUNT>, C::Nonce), CeremonyError<C>>>(
            "start", &identity,
        )
        .await
        .map_err(|_| {
            CeremonyError::Network(
                "Should have received starting meta data from server".to_string(),
            )
        })?
}
