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

//! Signer HTTP Client Implementation

use crate::config::Config;
use manta_accounting::{
    transfer::{canonical::Transaction, ReceivingKey},
    wallet::{
        self,
        signer::{
            self, ReceivingKeyRequest, SignError, SignResponse, SyncError, SyncRequest,
            SyncResponse,
        },
    },
};
use manta_util::serde::Serialize;
use reqwest::{
    blocking::{Client as BaseClient, Response},
    Error, IntoUrl, Method, Url,
};

/// Wallet Associated to [`Client`]
pub type Wallet<L> = wallet::Wallet<Config, L, Client>;

/// HTTP Client
pub struct Client {
    /// Server URL
    server_url: Url,

    /// Base HTTP Client
    client: BaseClient,
}

impl Client {
    /// Builds a new HTTP [`Client`] that connects to `server_url`.
    #[inline]
    pub fn new<U>(server_url: U) -> Result<Self, Error>
    where
        U: IntoUrl,
    {
        Ok(Self {
            client: BaseClient::builder().build()?,
            server_url: server_url.into_url()?,
        })
    }

    /// Sends a new request of type `command` with body `request`.
    #[inline]
    fn request<T>(&self, method: Method, command: &str, request: T) -> Result<Response, Error>
    where
        T: Serialize,
    {
        self.client
            .request(
                method,
                self.server_url
                    .join(command)
                    .expect("This error branch is not allowed to happen."),
            )
            .json(&request)
            .send()
    }

    /// Sends a GET request of type `command` with body `request`.
    #[inline]
    fn get<T>(&self, command: &str, request: T) -> Result<Response, Error>
    where
        T: Serialize,
    {
        self.request(Method::GET, command, request)
    }

    /// Sends a POST request of type `command` with body `request`.
    #[inline]
    fn post<T>(&self, command: &str, request: T) -> Result<Response, Error>
    where
        T: Serialize,
    {
        self.request(Method::POST, command, request)
    }
}

impl signer::Connection<Config> for Client {
    type Error = Error;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest<Config>,
    ) -> Result<Result<SyncResponse, SyncError>, Self::Error> {
        // NOTE: The synchronization command modifies the signer so it must be a POST command
        //       to match the HTTP semantics.
        self.post("sync", request)?.json()
    }

    #[inline]
    fn sign(
        &mut self,
        transaction: Transaction<Config>,
    ) -> Result<Result<SignResponse<Config>, SignError<Config>>, Self::Error> {
        // NOTE: The signing command does not modify the signer so it must be a GET command to match
        //       the HTTP semantics.
        self.get("sign", transaction)?.json()
    }

    #[inline]
    fn receiving_keys(
        &mut self,
        request: ReceivingKeyRequest,
    ) -> Result<Vec<ReceivingKey<Config>>, Self::Error> {
        // NOTE: The receiving key command modifies the signer so it must be a POST command to match
        //       the HTTP semantics.
        self.post("receivingKeys", request)?.json()
    }
}
