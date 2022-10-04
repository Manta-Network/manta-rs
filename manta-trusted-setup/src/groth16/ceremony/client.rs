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
            message::{ContributeRequest, ContributeResponse, QueryRequest, QueryResponse},
            Ceremony, CeremonyError, Metadata, Round, UnexpectedError,
        },
        mpc,
    },
};
use alloc::vec::Vec;
use console::Term;
use manta_crypto::rand::OsRng;
use manta_util::{
    http::reqwest::{self, IntoUrl, KnownUrlClient},
    ops::ControlFlow,
    serde::{de::DeserializeOwned, Serialize},
};
use tokio::time::{sleep, Duration};

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
        println!("{}", err);
        CeremonyError::Network
    }
}

/// Client Continuation States
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Continue {
    /// Position Updated
    Position(u64),

    /// Timeout
    Timeout,
}

/// Client Update States
pub type Update<C> = ControlFlow<ContributeResponse<C>, Continue>;

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
        let mut client_data = client
            .post::<_, Result<(Metadata, C::Nonce), CeremonyError<C>>>("start", &identifier)
            .await
            .map_err(into_ceremony_error);
        let term = Term::stdout();
        let mut counter = 0u8;
        println!("Connecting to server for Metadata");
        while let Err(CeremonyError::NotRegistered) = client_data {
            if counter >= 60 {
                panic!("This is taking longer than expected, please try again later.");
            }
            term.clear_last_lines(1)
                .expect("Clear last lines should succeed.");
            println!("Waiting for server registry update. Please make sure you are registered.");
            sleep(Duration::from_millis(10000)).await;
            client_data = client
                .post("start", &identifier)
                .await
                .map_err(into_ceremony_error);
            counter += 1;
        }
        let (metadata, nonce) = client_data??;
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
        C::Nonce: DeserializeOwned + Serialize,
        C::Signature: Serialize,
        QueryResponse<C>: DeserializeOwned,
    {
        let signed_message = self.sign(QueryRequest)?;
        match self
            .client
            .post::<_, Result<QueryResponse<C>, CeremonyError<C>>>("query", &signed_message)
            .await
        {
            Ok(Ok(QueryResponse::State(state))) => match state.with_valid_shape() {
                Some(state) if self.metadata.ceremony_size.matches(&state.state) => {
                    Ok(QueryResponse::State(state))
                }
                _ => Err(CeremonyError::Unexpected(
                    UnexpectedError::IncorrectStateSize,
                )),
            },
            Ok(Ok(response)) => Ok(response),
            Err(err) => Err(into_ceremony_error(err)),
            Ok(Err(err)) => Err(err),
        }
    }

    /// Performs the ceremony contribution over `round`, sending the result to the ceremony server.
    #[inline]
    async fn update(
        &mut self,
        hasher: &C::Hasher,
        mut round: Round<C>,
    ) -> Result<ContributeResponse<C>, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: DeserializeOwned + Serialize,
        C::Signature: Serialize,
        ContributeRequest<C>: Serialize,
        ContributeResponse<C>: DeserializeOwned,
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
            .post::<_, Result<ContributeResponse<C>, CeremonyError<C>>>("update", &signed_message)
            .await
            .map_err(into_ceremony_error)?
    }

    /// Tries to contribute to the ceremony if at the front of the queue. This method returns an
    /// [`Update`] if the status of the unfinalized participant has changed. If the result
    /// is `Ok(Response::Break)` then the ceremony contribution was successful and the success
    /// response is returned
    #[inline]
    pub async fn try_contribute(&mut self) -> Result<Update<C>, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: DeserializeOwned + Serialize,
        C::Signature: Serialize,
        QueryResponse<C>: DeserializeOwned,
        ContributeRequest<C>: Serialize,
        ContributeResponse<C>: DeserializeOwned,
    {
        let state = match self.query().await {
            Ok(QueryResponse::State(state)) => state,
            Ok(QueryResponse::QueuePosition(position)) => {
                return Ok(Update::Continue(Continue::Position(position)))
            }
            Err(CeremonyError::Timeout) => return Ok(Update::Continue(Continue::Timeout)),
            Err(err) => return Err(err),
        };
        match self.update(&C::Hasher::default(), state).await {
            Ok(response) => Ok(Update::Break(response)),
            Err(CeremonyError::Timeout) | Err(CeremonyError::NotYourTurn) => {
                Ok(Update::Continue(Continue::Timeout))
            }
            Err(err) => Err(err),
        }
    }
}

/// Runs the contribution protocol for `signing_key`, `identifier`, and `server_url`, using
/// `process_continuation` as the callback for processing [`Continue`] messages from the client.
#[inline]
pub async fn contribute<C, U, F>(
    signing_key: C::SigningKey,
    identifier: C::Identifier,
    server_url: U,
    mut process_continuation: F,
) -> Result<ContributeResponse<C>, CeremonyError<C>>
where
    C: Ceremony,
    C::Identifier: Serialize,
    C::Nonce: DeserializeOwned + Serialize,
    C::Signature: Serialize,
    QueryResponse<C>: DeserializeOwned,
    ContributeRequest<C>: Serialize,
    ContributeResponse<C>: DeserializeOwned,
    U: IntoUrl,
    F: FnMut(&Metadata, Continue),
{
    let mut client = Client::build(
        signing_key,
        identifier,
        KnownUrlClient::new(server_url).map_err(into_ceremony_error)?,
    )
    .await?;
    loop {
        match client.try_contribute().await {
            Ok(Update::Continue(update)) => process_continuation(&client.metadata, update),
            Ok(Update::Break(response)) => return Ok(response),
            Err(CeremonyError::InvalidSignature { expected_nonce }) => {
                client.update_nonce(expected_nonce)?;
            }
            Err(err) => return Err(err),
        }
    }
}
