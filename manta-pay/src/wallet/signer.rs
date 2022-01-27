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

//! Signer Client and Server

// TODO: Make this generic over the `Config`.

use crate::{config::Config, wallet::SignerBase};
use manta_accounting::{
    transfer::{canonical::Transaction, EncryptedNote, Utxo, VoidNumber},
    wallet::{
        signer,
        signer::{ReceivingKeyResult, SignResult, SyncResult},
    },
};
use std::net::TcpStream;
use tungstenite::{
    client::IntoClientRequest,
    handshake::server::{NoCallback, ServerHandshake},
    stream::MaybeTlsStream,
};

/// Stream Type
pub type Stream = MaybeTlsStream<TcpStream>;

/// Web Socket Connection Type
pub type WebSocket = tungstenite::WebSocket<Stream>;

/// Handshake Error Type
pub type HandshakeError =
    tungstenite::handshake::HandshakeError<ServerHandshake<Stream, NoCallback>>;

/// Client
pub struct Client {
    /// Underlying Client Connection
    connection: WebSocket,
}

impl Client {
    /// Builds a new [`Client`] from Web Socket `url`.
    #[inline]
    pub fn new<U>(url: U) -> Result<Self, tungstenite::error::Error>
    where
        U: IntoClientRequest,
    {
        Ok(Self {
            connection: tungstenite::connect(url)?.0,
        })
    }
}

impl signer::Connection<Config> for Client {
    type Error = ();

    #[inline]
    fn sync<I, R>(
        &mut self,
        starting_index: usize,
        inserts: I,
        removes: R,
    ) -> SyncResult<Config, Self>
    where
        I: IntoIterator<Item = (Utxo<Config>, EncryptedNote<Config>)>,
        R: IntoIterator<Item = VoidNumber<Config>>,
    {
        todo!()
    }

    #[inline]
    fn sign(&mut self, transaction: Transaction<Config>) -> SignResult<Config, Self> {
        todo!()
    }

    #[inline]
    fn receiving_key(&mut self) -> ReceivingKeyResult<Config, Self> {
        todo!()
    }
}

/// Signer Server
pub struct Server {
    /// Signer Base
    base: SignerBase,

    /// Underlying Server Connection
    connection: WebSocket,
}

impl Server {
    /// Builds a new [`Server`] from a [`Stream`].
    #[inline]
    pub fn new(stream: Stream) -> Result<Self, HandshakeError> {
        /* TODO:
        Ok(Self {
            connection: tungstenite::accept(stream)?,
        })
        */
        todo!()
    }
}
