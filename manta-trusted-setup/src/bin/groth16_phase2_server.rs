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

//! Groth16 Phase2 Servers

use manta_trusted_setup::{
    ceremony::{
        queue::{Identifier, Priority},
        server::{HasNonce, Server},
        signature::{
            ed_dalek,
            ed_dalek::{Ed25519, PublicKey},
            HasPublicKey,
        },
        CeremonyError,
    },
    groth16::{config::Config, mpc::Groth16Phase2},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tide::{prelude::*, Request};

/// Participant
#[derive(Clone, Serialize, Deserialize)]
struct Participant {
    pub public_key: ed_dalek::PublicKey,
    pub priority: usize,
    pub nonce: u64,
}

impl Priority for Participant {
    fn priority(&self) -> usize {
        self.priority
    }
}

impl Identifier for Participant {
    type Identifier = ed_dalek::PublicKey;

    fn identifier(&self) -> Self::Identifier {
        self.public_key
    }
}

impl HasPublicKey for Participant {
    type PublicKey = ed_dalek::PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key
    }
}

impl HasNonce<ed_dalek::Ed25519> for Participant {
    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn update_nonce(&mut self, nonce: u64) -> Result<(), CeremonyError> {
        if self.nonce >= nonce {
            return Err(CeremonyError::InvalidNonce);
        }
        self.nonce = nonce;
        Ok(())
    }
}

type S = Server<Groth16Phase2<Config>, Participant, BTreeMap<PublicKey, Participant>, Ed25519, 2>;

fn init_server() -> S {
    // TODO: read phase 1 accumulator from file
    // TODO: read high-priority participants from file
    // TODO: initialize registry and coordinator
    todo!()
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut api = tide::Server::with_state(init_server());

    api.at("/register")
        .post(|r| Server::execute(r, Server::register_participant));
    // TODO: implement serialize for `V::State`, `V::Proof`, `V::Challenge`
    api.at("/query")
        .post(|r| Server::execute(r, Server::get_state_and_challenge));
    api.at("/update")
        .post(|r| Server::execute(r, Server::update));
    api.listen("127.0.0.1:8080").await?;
    Ok(())

    /*
    let mut api = tide::Server::with_state(init_server());

    api.at("/register")
        .post(|r| Server::execute(r, Server::register_participant));
    api.at("/get_state_and_challenge")
        .post(|r| Server::execute(r, Server::get_state_and_challenge));
    api.at("/update")
        .post(|r| Server::execute(r, Server::update));

    api.listen("127.0.0.1:8080").await?;

    Ok(())
    */
}
//
// // ///
// // pub enum Error {
// //     ///
// //     AlreadyQueued,
//
// //     ///
// //     InvalidSignature,
//
// //     ///
// //     CeremonyError(CeremonyError),
// // }
//
// // impl From<Error> for tide::Error {
// //     #[inline]
// //     fn from(err: Error) -> tide::Error {
// //         match err {
// //             _ => Self::from_str(
// //                 StatusCode::InternalServerError,
// //                 "unable to complete request",
// //             ),
// //         }
// //     }
// // }
//
// // impl From<CeremonyError> for Error {
// //     #[inline]
// //     fn from(e: CeremonyError) -> Self {
// //         Self::CeremonyError(e)
// //     }
// // }
//
// // /// Result Type
// // pub type Result<T, E = Error> = core::result::Result<T, E>;
//
// // /// Generates the JSON body for the output of `f`, returning an HTTP reponse.
// // #[inline]
// // async fn into_body<R, F, Fut>(f: F) -> Result<Response, tide::Error>
// // where
// //     R: Serialize,
// //     F: FnOnce() -> Fut,
// //     Fut: Future<Output = Result<R>>,
// // {
// //     Ok(Body::from_json(&f().await?)?.into())
// // }
