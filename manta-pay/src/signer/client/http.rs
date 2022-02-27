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
    config::{Config, ReceivingKey, Transaction},
    signer::{ReceivingKeyRequest, SignError, SignResponse, SyncError, SyncRequest, SyncResponse},
    util::http::{self, Error, IntoUrl},
};
use alloc::vec::Vec;
use manta_accounting::wallet::{self, signer};

/// Wallet Associated to [`Client`]
pub type Wallet<L> = wallet::Wallet<Config, L, Client>;

/// HTTP Signer Client
pub struct Client(http::Client);

impl Client {
    /// Builds a new HTTP [`Client`] that connects to `server_url`.
    #[inline]
    pub fn new<U>(server_url: U) -> Result<Self, Error>
    where
        U: IntoUrl,
    {
        Ok(Self(http::Client::new(server_url)?))
    }
}

impl signer::Connection<Config> for Client {
    type Error = Error;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest,
    ) -> Result<Result<SyncResponse, SyncError>, Self::Error> {
        // NOTE: The synchronization command modifies the signer so it must be a POST command
        //       to match the HTTP semantics.
        self.0.post("sync", request)
    }

    #[inline]
    fn sign(
        &mut self,
        transaction: Transaction,
    ) -> Result<Result<SignResponse, SignError>, Self::Error> {
        // NOTE: The signing command does not modify the signer so it must be a GET command to match
        //       the HTTP semantics.
        self.0.get("sign", transaction)
    }

    #[inline]
    fn receiving_keys(
        &mut self,
        request: ReceivingKeyRequest,
    ) -> Result<Vec<ReceivingKey>, Self::Error> {
        // NOTE: The receiving key command modifies the signer so it must be a POST command to match
        //       the HTTP semantics.
        self.0.post("receivingKeys", request)
    }
}
