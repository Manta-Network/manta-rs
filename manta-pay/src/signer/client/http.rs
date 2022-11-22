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
    config::{utxo::protocol_pay, Config},
    signer::{
        client::network::{Network, Message},
        Checkpoint, GetRequest, SignError, SignRequest, SignResponse, SyncError, SyncRequest,
        SyncResponse,
    },
};
use alloc::boxed::Box;
use manta_accounting::wallet::{self, signer};
use manta_util::{
    future::LocalBoxFutureResult,
    http::reqwest::{self, IntoUrl, KnownUrlClient},
};

#[doc(inline)]
pub use reqwest::Error;

/// Wallet Associated to [`Client`]
pub type Wallet<L> = wallet::Wallet<Config, L, Client>;

/// HTTP Signer Client
pub struct Client {
    /// Base Client
    base: KnownUrlClient,

    /// Network Selector
    network: Option<Network>,
}

impl Client {
    /// Builds a new HTTP [`Client`] that connects to `server_url`.
    #[inline]
    pub fn new<U>(server_url: U) -> Result<Self, Error>
    where
        U: IntoUrl,
    {
        Ok(Self {
            base: KnownUrlClient::new(server_url)?,
            network: None,
        })
    }

    /// Sets the network that will be used to wrap HTTP requests.
    #[inline]
    pub fn set_network(&mut self, network: Option<Network>) {
        self.network = network
    }

    /// Wraps the current outgoing `request` with a `network` if it is not `None`.
    #[inline]
    pub fn wrap_request<T>(&self, request: T) -> Message<T> {
        Message {
            network: self
                .network
                .expect("Unable to wrap request, missing network."),
            message: request,
        }
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
        Box::pin(async move { self.base.post("sync", &request).await })
    }

    #[inline]
    fn sign(
        &mut self,
        request: SignRequest,
    ) -> LocalBoxFutureResult<Result<SignResponse, SignError>, Self::Error> {
        Box::pin(async move { self.base.post("sign", &request).await })
    }

    #[inline]
    fn address(&mut self) -> LocalBoxFutureResult<protocol_pay::Address, Self::Error> {
        Box::pin(async move { self.base.post("address", &GetRequest::Get).await })
    }
}
