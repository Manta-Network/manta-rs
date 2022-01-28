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
    transfer::{canonical::Transaction, EncryptedNote, ReceivingKey, Utxo, VoidNumber},
    wallet::signer::{
        self, ReceivingKeyResult, SignResponse, SignResult, SyncResponse, SyncResult,
    },
};
use manta_util::{
    convert::{From, TryFrom},
    message::{ChannelError, MessageProtocol, ParsingError, UniformChannel},
};
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

///
pub struct WebSocket(tungstenite::WebSocket<Stream>);

impl UniformChannel for WebSocket {
    type Message = Message;
    type ReadError = Error;
    type WriteError = Error;

    #[inline]
    fn read(&mut self) -> Result<Self::Message, Self::ReadError> {
        self.0.read_message()
    }

    #[inline]
    fn write(&mut self, message: Self::Message) -> Result<(), Self::WriteError> {
        self.0.write_message(message)
    }
}

///
pub struct Synchronize;

///
pub struct SyncRequest {
    ///
    starting_index: usize,

    ///
    inserts: Vec<(Utxo<Config>, EncryptedNote<Config>)>,

    ///
    removes: Vec<VoidNumber<Config>>,
}

impl From<SyncRequest, WebSocket> for Message {
    #[inline]
    fn from(request: SyncRequest) -> Self {
        todo!()
    }
}

impl TryFrom<Message, WebSocket> for SyncRequest {
    type Error = ();

    #[inline]
    fn try_from(message: Message) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<SyncResponse, WebSocket> for Message {
    #[inline]
    fn from(response: SyncResponse) -> Self {
        todo!()
    }
}

impl TryFrom<Message, WebSocket> for SyncResponse {
    type Error = ();

    #[inline]
    fn try_from(message: Message) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl MessageProtocol for Synchronize {
    type Request = SyncRequest;
    type Response = SyncResponse;
    type Client = WebSocket;
    type Server = WebSocket;
}

///
pub struct Sign;

impl From<Transaction<Config>, WebSocket> for Message {
    #[inline]
    fn from(request: Transaction<Config>) -> Message {
        todo!()
    }
}

impl TryFrom<Message, WebSocket> for Transaction<Config> {
    type Error = ();

    #[inline]
    fn try_from(message: Message) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<SignResponse<Config>, WebSocket> for Message {
    #[inline]
    fn from(response: SignResponse<Config>) -> Self {
        todo!()
    }
}

impl TryFrom<Message, WebSocket> for SignResponse<Config> {
    type Error = ();

    #[inline]
    fn try_from(message: Message) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl MessageProtocol for Sign {
    type Request = Transaction<Config>;
    type Response = SignResponse<Config>;
    type Client = WebSocket;
    type Server = WebSocket;
}

/// Client
pub struct Client {
    /// Underlying Connection
    connection: WebSocket,
}

impl Client {
    /// Builds a new [`Client`] from Web Socket `url`.
    #[inline]
    pub fn new<U>(url: U) -> Result<Self, Error>
    where
        U: IntoClientRequest,
    {
        Ok(Self {
            connection: WebSocket(tungstenite::connect(url)?.0),
        })
    }
}

impl signer::Connection<Config> for Client {
    type Error = ParsingError<Error, ()>;

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
        Synchronize::send(
            &mut self.connection,
            SyncRequest {
                starting_index,
                inserts: inserts.into_iter().collect(),
                removes: removes.into_iter().collect(),
            },
        )
        .map_err(ChannelError::into_parsing_error)
    }

    #[inline]
    fn sign(&mut self, transaction: Transaction<Config>) -> SignResult<Config, Self> {
        Sign::send(&mut self.connection, transaction).map_err(ChannelError::into_parsing_error)
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

    /// Underlying Connection
    connection: Option<WebSocket>,
}

impl Server {
    /// Builds a new [`Server`] from `base`.
    #[inline]
    pub fn new(base: SignerBase) -> Self {
        Self {
            base,
            connection: None,
        }
    }

    ///
    #[inline]
    pub fn connect(&mut self, stream: Stream) -> Result<(), HandshakeError> {
        self.connection = Some(WebSocket(tungstenite::accept(stream)?));
        Ok(())
    }
}
