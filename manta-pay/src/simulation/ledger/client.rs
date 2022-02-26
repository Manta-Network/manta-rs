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
    config::{Config, EncryptedNote, TransferPost, Utxo, VoidNumber},
    simulation::ledger::{AccountId, Checkpoint},
    util::http::{self, Error, IntoUrl},
};
use manta_accounting::wallet::ledger::{self, PullResult, PushResult};
use manta_util::serde::{Deserialize, Serialize};

/// HTTP Ledger Client
pub struct Client {
    /// Account Id
    account: AccountId,

    /// Client Connection
    client: http::Client,
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
            client: http::Client::new(server_url)?,
        })
    }
}

/// HTTP Client Request
#[derive(Deserialize, Serialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
struct Request<T> {
    /// Account Id
    account: AccountId,

    /// Request Payload
    request: T,
}

impl ledger::Connection<Config> for Client {
    type Checkpoint = Checkpoint;
    type ReceiverChunk = Vec<(Utxo, EncryptedNote)>;
    type SenderChunk = Vec<VoidNumber>;
    type Error = Error;

    #[inline]
    fn pull(&mut self, checkpoint: &Self::Checkpoint) -> PullResult<Config, Self> {
        // NOTE: The pull command does not modify the ledger so it must be a GET command to match
        //       the HTTP semantics.
        self.client.get(
            "pull",
            Request {
                account: self.account,
                request: checkpoint,
            },
        )
    }

    #[inline]
    fn push(&mut self, posts: Vec<TransferPost>) -> PushResult<Config, Self> {
        // NOTE: The push command modifies the ledger so it must be a POST command to match the
        //       HTTP semantics.
        self.client.post(
            "push",
            Request {
                account: self.account,
                request: posts,
            },
        )
    }
}
