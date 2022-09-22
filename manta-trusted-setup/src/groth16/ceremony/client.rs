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
    ceremony::signature::{SignedMessage, Signer},
    groth16::{
        ceremony::{
            message::{ContributeRequest, QueryRequest, QueryResponse},
            Ceremony, CeremonyError, Metadata, Round, UnexpectedError,
        },
        mpc,
    },
};
use alloc::vec::Vec;
use manta_crypto::rand::OsRng;
use manta_util::{
    http::reqwest::{self, IntoUrl, KnownUrlClient},
    serde::{de::DeserializeOwned, Serialize},
};

/// Converts the [`reqwest`] error `err` into a [`CeremonyError`] depending on whether it comes from
/// a timeout or other network error.
#[inline]
fn into_ceremony_error<C>(err: reqwest::Error) -> CeremonyError<C>
where
    C: Ceremony,
{
    if err.is_timeout() {
        CeremonyError::Timeout
    } else {
        CeremonyError::Network
    }
}

/// Client Update States
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Update {
    /// Position Updated
    Position(u64),

    /// Timeout
    Timeout,
}

/// Client
pub struct Client<C>
where
    C: Ceremony,
{
    /// Signer
    signer: Signer<C, C::Identifier>,

    /// HTTP Client
    client: KnownUrlClient,

    /// Ceremony Metadata
    metadata: Metadata,
}

impl<C> Client<C>
where
    C: Ceremony,
{
    /// Builds a new [`Client`] from `signer`, `client`, and `ceremony_size`.
    #[inline]
    fn new_unchecked(
        signer: Signer<C, C::Identifier>,
        client: KnownUrlClient,
        metadata: Metadata,
    ) -> Self {
        Self {
            signer,
            client,
            metadata,
        }
    }

    /// Updates the client's nonce to the `expected_nonce` returned by the server.
    #[inline]
    fn update_nonce(&mut self, expected_nonce: C::Nonce) -> Result<(), CeremonyError<C>> {
        self.signer
            .set_valid_nonce(expected_nonce)
            .then_some(())
            .ok_or(CeremonyError::Unexpected(UnexpectedError::AllNoncesUsed))
    }

    /// Signs the `message` with the signer in `self`, incrementing its nonce if the signing was
    /// successful.
    #[inline]
    fn sign<T>(
        &mut self,
        message: T,
    ) -> Result<SignedMessage<C, C::Identifier, T>, CeremonyError<C>>
    where
        T: Serialize,
    {
        let signed_message = self
            .signer
            .sign(message)
            .map_err(|_| CeremonyError::Unexpected(UnexpectedError::Serialization))?;
        self.signer.increment_nonce();
        Ok(signed_message)
    }

    /// Builds a new [`Client`] from `signing_key`, `identifier`, and `client` and performs the
    /// initial synchronization procedure with the ceremony server to establish the correct ceremony
    /// parameters and registration status.
    #[inline]
    pub async fn build(
        signing_key: C::SigningKey,
        identifier: C::Identifier,
        client: KnownUrlClient,
    ) -> Result<Self, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: DeserializeOwned,
    {
        let (metadata, nonce) = client
            .post("start", &identifier)
            .await
            .map_err(into_ceremony_error)?;
        Ok(Self::new_unchecked(
            Signer::new(nonce, signing_key, identifier),
            client,
            metadata,
        ))
    }

    /// Queries for the state of the ceremony, returning the queue position if the participant is
    /// not at the front of the queue.
    #[inline]
    async fn query(&mut self) -> Result<QueryResponse<C>, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: Serialize,
        C::Signature: Serialize,
        QueryResponse<C>: DeserializeOwned,
    {
        let signed_message = self.sign(QueryRequest)?;
        match self.client.post("query", &signed_message).await {
            Ok(QueryResponse::State(state)) => match state.with_valid_shape() {
                Some(state) if self.metadata.ceremony_size.matches(&state.state) => {
                    Ok(QueryResponse::State(state))
                }
                _ => Err(CeremonyError::Unexpected(
                    UnexpectedError::IncorrectStateSize,
                )),
            },
            Ok(response) => Ok(response),
            Err(err) => Err(into_ceremony_error(err)),
        }
    }

    /// Performs the ceremony contribution over `round`, sending the result to the ceremony server.
    #[inline]
    async fn contribute(
        &mut self,
        hasher: &C::Hasher,
        mut round: Round<C>,
    ) -> Result<(), CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: Serialize,
        C::Signature: Serialize,
        ContributeRequest<C>: Serialize,
    {
        let mut rng = OsRng;
        let mut proof = Vec::new();
        for i in 0..round.state.len() {
            proof.push(
                mpc::contribute(hasher, &round.challenge[i], &mut round.state[i], &mut rng).ok_or(
                    CeremonyError::Unexpected(UnexpectedError::FailedContribution),
                )?,
            );
        }
        let signed_message = self.sign(ContributeRequest {
            state: round.state.into(),
            proof,
        })?;
        self.client
            .post("update", &signed_message)
            .await
            .map_err(into_ceremony_error)
    }

    /// Tries to contribute to the ceremony if at the front of the queue. This method returns an
    /// optional [`Update`] if the status of the unfinalized participant has changed. If the result
    /// is `Ok(None)` then the ceremony contribution was successful.
    #[inline]
    pub async fn try_contribute(&mut self) -> Result<Option<Update>, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: Serialize,
        C::Signature: Serialize,
        ContributeRequest<C>: Serialize,
        QueryResponse<C>: DeserializeOwned,
    {
        let state = match self.query().await {
            Ok(QueryResponse::State(state)) => state,
            Ok(QueryResponse::QueuePosition(position)) => {
                return Ok(Some(Update::Position(position)))
            }
            Err(CeremonyError::Timeout) => return Ok(Some(Update::Timeout)),
            Err(err) => return Err(err),
        };
        match self.contribute(&C::Hasher::default(), state).await {
            Ok(_) => Ok(None),
            Err(CeremonyError::Timeout) | Err(CeremonyError::NotYourTurn) => {
                Ok(Some(Update::Timeout))
            }
            Err(err) => Err(err),
        }
    }
}

/// Runs the contribution protocol for `signing_key`, `identifier`, and `server_url`, using
/// `process_update` as the callback for processing [`Update`] messages from the client.
#[inline]
pub async fn contribute<C, U, F>(
    signing_key: C::SigningKey,
    identifier: C::Identifier,
    server_url: U,
    mut process_update: F,
) -> Result<(), CeremonyError<C>>
where
    C: Ceremony,
    C::Identifier: Serialize,
    C::Nonce: DeserializeOwned + Serialize,
    C::Signature: Serialize,
    ContributeRequest<C>: Serialize,
    QueryResponse<C>: DeserializeOwned,
    U: IntoUrl,
    F: FnMut(Update),
{
    let mut client = Client::build(
        signing_key,
        identifier,
        KnownUrlClient::new(server_url).map_err(into_ceremony_error)?,
    )
    .await?;
    loop {
        match client.try_contribute().await {
            Ok(Some(update)) => process_update(update),
            Ok(None) => return Ok(()),
            Err(CeremonyError::InvalidSignature { expected_nonce }) => {
                client.update_nonce(expected_nonce)?;
            }
            Err(err) => return Err(err),
        }
    }
}
