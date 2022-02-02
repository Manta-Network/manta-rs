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

//! Signer WebSocket Client Implementation

use crate::config::Config;
use manta_accounting::{
    transfer::{canonical::Transaction, ReceivingKey},
    wallet::signer::{self, SignError, SignResponse, SyncError, SyncRequest, SyncResponse},
};
use manta_util::codec::Encode;
use std::net::TcpStream;
use tungstenite::{
    client::IntoClientRequest,
    handshake::server::{NoCallback, ServerHandshake},
    stream::MaybeTlsStream,
    Message,
};

/// Stream Type
pub type Stream = MaybeTlsStream<TcpStream>;

/// Error Type
pub type Error = tungstenite::error::Error;

/// Handshake Error Type
pub type HandshakeError =
    tungstenite::handshake::HandshakeError<ServerHandshake<Stream, NoCallback>>;

/// WebSocket Client
pub struct Client(tungstenite::WebSocket<Stream>);

impl Client {
    /// Builds a new [`Client`] from `url`.
    #[inline]
    pub fn new<U>(url: U) -> Result<Self, Error>
    where
        U: IntoClientRequest,
    {
        Ok(Self(tungstenite::connect(url)?.0))
    }
}

impl signer::Connection<Config> for Client {
    type Error = ();

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest<Config>,
    ) -> Result<Result<SyncResponse, SyncError>, Self::Error> {
        todo!()
    }

    #[inline]
    fn sign(
        &mut self,
        transaction: Transaction<Config>,
    ) -> Result<Result<SignResponse<Config>, SignError<Config>>, Self::Error> {
        todo!()
    }

    #[inline]
    fn receiving_key(&mut self) -> Result<ReceivingKey<Config>, Self::Error> {
        todo!()
    }
}
