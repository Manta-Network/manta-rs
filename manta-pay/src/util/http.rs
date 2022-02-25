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

//! HTTP Utilities

use manta_util::serde::Serialize;
use reqwest::blocking;

pub use reqwest::{blocking::Response, Error, IntoUrl, Method, Url};

/// Blocking HTTP Client
///
/// This client is a wrapper around [`reqwest::blocking::Client`] which has a known server URL.
pub struct Client {
    /// Server URL
    pub server_url: Url,

    /// Base HTTP Client
    pub client: blocking::Client,
}

impl Client {
    /// Builds a new HTTP [`Client`] that connects to `server_url`.
    #[inline]
    pub fn new<U>(server_url: U) -> Result<Self, Error>
    where
        U: IntoUrl,
    {
        Ok(Self {
            client: blocking::Client::builder().build()?,
            server_url: server_url.into_url()?,
        })
    }

    /// Sends a new request of type `command` with body `request`.
    #[inline]
    pub fn request<T>(&self, method: Method, command: &str, request: T) -> Result<Response, Error>
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
    pub fn get<T>(&self, command: &str, request: T) -> Result<Response, Error>
    where
        T: Serialize,
    {
        self.request(Method::GET, command, request)
    }

    /// Sends a POST request of type `command` with body `request`.
    #[inline]
    pub fn post<T>(&self, command: &str, request: T) -> Result<Response, Error>
    where
        T: Serialize,
    {
        self.request(Method::POST, command, request)
    }
}
