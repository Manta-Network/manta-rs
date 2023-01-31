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
    config::{utxo::Address, Config},
    signer::{
        client::network::{Message, Network},
        stateless_signer::{
            self, StatelessAddressRequest, StatelessIdentityRequest, StatelessSignRequest,
            StatelessSignResult, StatelessSyncRequest, StatelessSyncResult,
            StatelessTransactionDataRequest,
        },
        AssetMetadata, Checkpoint, GetRequest, IdentityRequest, IdentityResponse, SignError,
        SignRequest, SignResponse, SyncError, SyncRequest, SyncResponse, TransactionDataRequest,
        TransactionDataResponse,
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
    type AssetMetadata = AssetMetadata;
    type Checkpoint = Checkpoint;
    type Error = Error;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest,
    ) -> LocalBoxFutureResult<Result<SyncResponse, SyncError>, Self::Error> {
        Box::pin(async move { self.base.post("sync", &self.wrap_request(request)).await })
    }

    #[inline]
    fn sign(
        &mut self,
        request: SignRequest,
    ) -> LocalBoxFutureResult<Result<SignResponse, SignError>, Self::Error> {
        Box::pin(async move { self.base.post("sign", &self.wrap_request(request)).await })
    }

    #[inline]
    fn address(&mut self) -> LocalBoxFutureResult<Address, Self::Error> {
        Box::pin(async move {
            self.base
                .post("address", &self.wrap_request(GetRequest::Get))
                .await
        })
    }

    #[inline]
    fn transaction_data(
        &mut self,
        request: TransactionDataRequest,
    ) -> LocalBoxFutureResult<TransactionDataResponse, Self::Error> {
        Box::pin(async move {
            self.base
                .post("transaction_data", &self.wrap_request(request))
                .await
        })
    }

    #[inline]
    fn identity_proof(
        &mut self,
        request: IdentityRequest,
    ) -> LocalBoxFutureResult<IdentityResponse, Self::Error> {
        Box::pin(async move {
            self.base
                .post("identity", &self.wrap_request(request))
                .await
        })
    }
}

impl stateless_signer::StatelessSignerConnection<Config> for Client {
    type Error = Error;

    #[inline]
    fn sync(
        &mut self,
        request: StatelessSyncRequest,
    ) -> LocalBoxFutureResult<StatelessSyncResult, Self::Error> {
        Box::pin(async move { self.base.post("sync", &self.wrap_request(request)).await })
    }

    #[inline]
    fn sign(
        &mut self,
        request: StatelessSignRequest,
    ) -> LocalBoxFutureResult<StatelessSignResult, Self::Error> {
        Box::pin(async move { self.base.post("sign", &self.wrap_request(request)).await })
    }

    #[inline]
    fn address(
        &mut self,
        request: StatelessAddressRequest,
    ) -> LocalBoxFutureResult<Address, Self::Error> {
        Box::pin(async move { self.base.post("address", &self.wrap_request(request)).await })
    }

    #[inline]
    fn transaction_data(
        &mut self,
        request: StatelessTransactionDataRequest,
    ) -> LocalBoxFutureResult<TransactionDataResponse, Self::Error> {
        Box::pin(async move {
            self.base
                .post("transaction_data", &self.wrap_request(request))
                .await
        })
    }

    #[inline]
    fn identity_proof(
        &mut self,
        request: StatelessIdentityRequest,
    ) -> LocalBoxFutureResult<IdentityResponse, Self::Error> {
        Box::pin(async move {
            self.base
                .post("identity", &self.wrap_request(request))
                .await
        })
    }
}
