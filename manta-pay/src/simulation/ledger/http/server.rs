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

//! Ledger Simulation Server

use crate::{
    config::{Config, TransferPost},
    simulation::ledger::{http::Request, AccountId, Checkpoint, Ledger, SharedLedger},
};
use alloc::sync::Arc;
use core::future::Future;
use manta_accounting::{
    asset::AssetList,
    wallet::{ledger::ReadResponse, signer::SyncData},
};
use manta_util::{
    http::tide::{self, listener::ToListener, Body, Response},
    serde::{de::DeserializeOwned, Serialize},
};
use tokio::{io, sync::RwLock};

/// Ledger HTTP Server State
#[derive(Clone, Debug)]
pub struct State(SharedLedger);

impl State {
    /// Builds a new server [`State`] from `ledger`.
    #[inline]
    pub fn new(ledger: Ledger) -> Self {
        Self(Arc::new(RwLock::new(ledger)))
    }

    /// Pulls data from the ledger at the given `checkpoint`.
    #[inline]
    async fn pull(
        self,
        account: AccountId,
        checkpoint: Checkpoint,
    ) -> ReadResponse<SyncData<Config>> {
        let _ = account;
        self.0.read().await.pull(&checkpoint)
    }

    /// Pushes data to the ledger with the given `account` and `posts`.
    #[inline]
    async fn push(self, account: AccountId, posts: Vec<TransferPost>) -> bool {
        self.0.write().await.push(account, posts)
    }

    /// Returns the public balances associated to `account` if they exist.
    #[inline]
    async fn public_balances(self, account: AccountId) -> Option<AssetList> {
        self.0.read().await.public_balances(account)
    }
}

/// Ledger HTTP Server
#[derive(Clone, Debug)]
pub struct Server(tide::Server<State>);

impl Server {
    /// Builds a new [`Server`] for `ledger`.
    #[inline]
    pub fn new(ledger: Ledger) -> Self {
        let mut api = tide::Server::with_state(State::new(ledger));
        api.at("/pull").get(|r| Self::execute_with(r, State::pull));
        api.at("/push").post(|r| Self::execute_with(r, State::push));
        api.at("/publicBalances")
            .post(|r| Self::execute(r, State::public_balances));
        Self(api)
    }

    /// Executes `f` on the incoming `request`.
    #[inline]
    async fn execute<R, F, Fut>(
        request: tide::Request<State>,
        f: F,
    ) -> Result<Response, tide::Error>
    where
        R: Serialize,
        F: FnOnce(State, AccountId) -> Fut,
        Fut: Future<Output = R>,
    {
        let account = request.query::<AccountId>()?;
        Self::into_body(move || async move { f(request.state().clone(), account).await }).await
    }

    /// Executes `f` on the incoming `request` parsing the full query.
    #[inline]
    async fn execute_with<T, R, F, Fut>(
        request: tide::Request<State>,
        f: F,
    ) -> Result<Response, tide::Error>
    where
        T: DeserializeOwned,
        R: Serialize,
        F: FnOnce(State, AccountId, T) -> Fut,
        Fut: Future<Output = R>,
    {
        let args = request.query::<Request<T>>()?;
        Self::into_body(move || async move {
            f(request.state().clone(), args.account, args.request).await
        })
        .await
    }

    /// Generates the JSON body for the output of `f`, returning an HTTP reponse.
    #[inline]
    async fn into_body<R, F, Fut>(f: F) -> Result<Response, tide::Error>
    where
        R: Serialize,
        F: FnOnce() -> Fut,
        Fut: Future<Output = R>,
    {
        Ok(Body::from_json(&f().await)?.into())
    }

    /// Serves `self` at the given `listener`.
    #[inline]
    pub async fn serve<L>(self, listener: L) -> Result<(), io::Error>
    where
        L: ToListener<State>,
    {
        self.0.listen(listener).await
    }
}
