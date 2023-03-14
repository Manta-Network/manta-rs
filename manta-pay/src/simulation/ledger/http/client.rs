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

//! Ledger Simulation Client

use crate::{
    config::{
        utxo::{AssetId, AssetValue},
        Config, TransferPost,
    },
    simulation::ledger::{http::Request, AccountId, Checkpoint},
};
use manta_accounting::{
    asset::AssetList,
    wallet::{
        ledger::{self, ReadResponse},
        signer::SyncData,
        test::PublicBalanceOracle,
    },
};
use manta_util::{
    future::{LocalBoxFuture, LocalBoxFutureResult},
    http::reqwest::{self, Error, IntoUrl, KnownUrlClient},
    serde::{de::DeserializeOwned, Serialize},
};

/// HTTP Ledger Client
pub struct Client {
    /// Account Id
    account: AccountId,

    /// Client Connection
    client: KnownUrlClient,
}

impl Client {
    /// Builds a new HTTP [`Client`] that connects to `server_url`.
    #[inline]
    pub fn new<U>(account: AccountId, server_url: U) -> Result<Self, Error>
    where
        U: IntoUrl,
    {
        Ok(Self {
            account,
            client: KnownUrlClient::new(server_url)?,
        })
    }

    ///
    #[inline]
    pub async fn post_request<T, R>(&self, command: &str, request: T) -> reqwest::Result<R>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        self.client
            .post(
                command,
                &Request {
                    account: self.account,
                    request,
                },
            )
            .await
    }
}

impl ledger::Connection for Client {
    type Error = Error;
}

impl ledger::Read<SyncData<Config>> for Client {
    type Checkpoint = Checkpoint;

    #[inline]
    fn read<'s>(
        &'s mut self,
        checkpoint: &'s Self::Checkpoint,
    ) -> LocalBoxFutureResult<'s, ReadResponse<SyncData<Config>>, Self::Error> {
        Box::pin(self.post_request("pull", checkpoint))
    }
}

impl ledger::Write<Vec<TransferPost>> for Client {
    type Response = bool;

    #[inline]
    fn write(
        &mut self,
        posts: Vec<TransferPost>,
    ) -> LocalBoxFutureResult<Self::Response, Self::Error> {
        Box::pin(self.post_request("push", posts))
    }
}

impl PublicBalanceOracle<Config> for Client {
    #[inline]
    fn public_balances(&self) -> LocalBoxFuture<Option<AssetList<AssetId, AssetValue>>> {
        Box::pin(async move {
            self.client
                .post("publicBalances", &self.account)
                .await
                .ok()
                .flatten()
        })
    }
}
