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

use crate::{
    config::{Config, ReceivingKey},
    signer::{
        Checkpoint, ReceivingKeyRequest, SignError, SignRequest, SignResponse, SyncError,
        SyncRequest, SyncResponse,
    },
};
use alloc::{boxed::Box, vec::Vec};
use manta_accounting::wallet::{self, signer};
use manta_signer::network::{Network,Message};
use manta_util::{
    future::LocalBoxFutureResult,
    http::reqwest::{self, IntoUrl, KnownUrlClient},
};

#[doc(inline)]
pub use reqwest::Error;

/// Wallet Associated to [`Client`]
pub type Wallet<L> = wallet::Wallet<Config, L, Client>;

/// HTTP Signer Client
pub struct Client(KnownUrlClient, Option<Network>);

impl Client {
    /// Builds a new HTTP [`Client`] that connects to `server_url`.
    #[inline]
    pub fn new<U>(server_url: U) -> Result<Self, Error>
    where
        U: IntoUrl,
    {
        Ok(Self(KnownUrlClient::new(server_url)?))
    }

    /// Sets the network that will be used to wrap HTTP requests.
    #[inline]
    pub fn set_network(self,network:Option<Network>) {
        self.1 = network;
    }

    /// Wraps the current outgoing Request with a network.
    #[inline]
    pub fn wrap_request<T>(self,request:T) -> Message<T> {
        Message {network: self.1, message:request}
    }
}

impl signer::Connection<Config> for Client {
    type Checkpoint = Checkpoint;
    type Error = Error;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest,
    ) -> LocalBoxFutureResult<Result<SyncResponse, SyncError>, Self::Error> {
        Box::pin(async move {
            let message = self.wrap_request(request);
            self.0.post("sync", &message).await
        })
    }

    #[inline]
    fn sign(
        &mut self,
        request: SignRequest
    ) -> LocalBoxFutureResult<Result<SignResponse, SignError>, Self::Error> {
        Box::pin(async move {
            let message = self.wrap_request(request);
            self.0.post("sign", &message).await
        })
    }

    #[inline]
    fn receiving_keys(
        &mut self,
        request: ReceivingKeyRequest,
    ) -> LocalBoxFutureResult<Vec<ReceivingKey>, Self::Error> {
        Box::pin(async move { self.0.post("receivingKeys", &request).await })
    }
}
