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
            Ceremony, CeremonyError, UnexpectedError,
        },
        mpc::{contribute, State},
    },
};
use manta_crypto::rand::OsRng;
use manta_util::{
    http::reqwest::KnownUrlClient,
    serde::{de::DeserializeOwned, Serialize},
};

/// Client
pub struct Client<C>
where
    C: Ceremony,
{
    /// Signer
    signer: Signer<C, C::Identifier>,

    /// HTTP Client
    client: KnownUrlClient,
}

impl<C> Client<C>
where
    C: Ceremony,
{
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
    pub async fn start(&self) -> Result<(CeremonySize, C::Nonce), CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: DeserializeOwned,
    {
        self.client
            .post("start", &self.signer.identifier())
            .await
            .map_err(|_| CeremonyError::Network("".into()))
    }

    ///
    #[inline]
    pub async fn query(&mut self) -> Result<QueryResponse<C>, CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: Serialize,
        C::Signature: Serialize,
        QueryResponse<C>: DeserializeOwned,
    {
        let signed_message = self.sign(QueryRequest)?;
        self.client
            .post("query", &signed_message)
            .await
            .map_err(|_| CeremonyError::Network("".into()))
    }

    ///
    #[inline]
    pub async fn contribute(
        &mut self,
        hasher: &C::Hasher,
        challenge: &[C::Challenge],
        mut state: Vec<State<C>>,
    ) -> Result<(), CeremonyError<C>>
    where
        C::Identifier: Serialize,
        C::Nonce: Serialize,
        C::Signature: Serialize,
        ContributeRequest<C>: Serialize,
    {
        let mut rng = OsRng;
        let mut proof = Vec::new();
        // FIXME: have to check challenge and state lengths are equal
        for i in 0..challenge.len() {
            proof.push(
                contribute(hasher, &challenge[i], &mut state[i], &mut rng).ok_or(
                    CeremonyError::Unexpected(UnexpectedError::FailedContribution),
                )?,
            );
        }
        let signed_message = self.sign(ContributeRequest { state, proof })?;
        self.client
            .post("update", &signed_message)
            .await
            .map_err(|_| CeremonyError::Network("".into()))
    }
}
