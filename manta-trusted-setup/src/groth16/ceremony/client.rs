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
            message::{CeremonySize, ContributeRequest, QueryRequest, QueryResponse},
            Ceremony, CeremonyError, Round, UnexpectedError,
        },
        mpc,
    },
};
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

    /// Ceremony Size
    ceremony_size: CeremonySize,
}

impl<C> Client<C>
where
    C: Ceremony,
{
    ///
    #[inline]
    fn new_unchecked(
        signer: Signer<C, C::Identifier>,
        client: KnownUrlClient,
        ceremony_size: CeremonySize,
    ) -> Self {
        Self {
            signer,
            client,
            ceremony_size,
        }
    }

    ///
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

    ///
    #[inline]
    pub async fn start(
        signing_key: C::SigningKey,
        identifier: C::Identifier,
        client: KnownUrlClient,
    ) -> Result<Self, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: DeserializeOwned,
    {
        let (ceremony_size, nonce) = client
            .post("start", &identifier)
            .await
            .map_err(into_ceremony_error)?;
        Ok(Self::new_unchecked(
            Signer::new(nonce, signing_key, identifier),
            client,
            ceremony_size,
        ))
    }

    ///
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
                Some(state) if self.ceremony_size.matches(&state.state) => {
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

    ///
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

    ///
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

///
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
    let mut client = Client::start(
        signing_key,
        identifier,
        KnownUrlClient::new(server_url).map_err(into_ceremony_error)?,
    )
    .await?;
    loop {
        match client.try_contribute().await {
            Ok(None) => return Ok(()),
            Ok(Some(update)) => process_update(update),
            Err(err) => return Err(err),
        }
    }
}
