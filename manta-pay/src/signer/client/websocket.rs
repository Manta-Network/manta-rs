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

use crate::{
    config::{Config, ReceivingKey},
    signer::{
        ReceivingKeyRequest, SignError, SignRequest, SignResponse, SyncError, SyncRequest,
        SyncResponse,
    },
};
use alloc::vec::Vec;
use manta_accounting::wallet::{self, signer};
use manta_util::{
    from_variant_impl,
    future::LocalBoxFutureResult,
    serde::{de::DeserializeOwned, Deserialize, Serialize},
};
use std::net::TcpStream;
use tungstenite::{client::IntoClientRequest, stream::MaybeTlsStream, Message};

/// Web Socket Error
pub type WebSocketError = tungstenite::error::Error;

/// Client Error
#[derive(Debug)]
pub enum Error {
    /// Invalid Message Format
    ///
    /// The message received from the WebSocket connection was not a [`Message::Text`].
    InvalidMessageFormat,

    /// Serialization Error
    SerializationError(serde_json::Error),

    /// WebSocket Error
    WebSocket(WebSocketError),
}

from_variant_impl!(Error, SerializationError, serde_json::Error);
from_variant_impl!(Error, WebSocket, WebSocketError);

/// Request
#[derive(derivative::Derivative, Deserialize, Serialize)]
#[serde(crate = "manta_util::serde")]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Request<R> {
    /// Request Command
    ///
    /// This command is used by the server to decide which command to execute the request on, and to
    /// parse the request correctly from the serialized data.
    pub command: &'static str,

    /// Request Body
    pub request: R,
}

/// Wallet Associated to [`Client`]
pub type Wallet<L> = wallet::Wallet<Config, L, Client>;

/// WebSocket Client
pub struct Client(tungstenite::WebSocket<MaybeTlsStream<TcpStream>>);

impl Client {
    /// Builds a new [`Client`] from `url`.
    #[inline]
    pub fn new<U>(url: U) -> Result<Self, WebSocketError>
    where
        U: IntoClientRequest,
    {
        Ok(Self(tungstenite::connect(url)?.0))
    }

    /// Sends a `request` for the given `command` along the channel and waits for the response.
    #[inline]
    async fn send<S, D>(&mut self, command: &'static str, request: S) -> Result<D, Error>
    where
        S: Serialize,
        D: DeserializeOwned,
    {
        /* TODO:
        self.0
            .write_message(Message::Text(serde_json::to_string(&Request {
                command,
                request,
            })?))?;
        match self.0.read_message()? {
            Message::Text(message) => Ok(serde_json::from_str(&message)?),
            _ => Err(Error::InvalidMessageFormat),
        }
        */
        todo!()
    }
}

impl signer::Connection<Config> for Client {
    type Error = Error;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest,
    ) -> LocalBoxFutureResult<Result<SyncResponse, SyncError>, Self::Error> {
        Box::pin(async move { self.send("sync", request).await })
    }

    #[inline]
    fn sign(
        &mut self,
        request: SignRequest,
    ) -> LocalBoxFutureResult<Result<SignResponse, SignError>, Self::Error> {
        Box::pin(async move { self.send("sign", request).await })
    }

    #[inline]
    fn receiving_keys(
        &mut self,
        request: ReceivingKeyRequest,
    ) -> LocalBoxFutureResult<Vec<ReceivingKey>, Self::Error> {
        Box::pin(async move { self.send("receivingKeys", request).await })
    }
}
