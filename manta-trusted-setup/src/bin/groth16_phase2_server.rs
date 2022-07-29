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
//! Waiting queue for the ceremony.
// use manta_trusted_setup::ceremony::CeremonyError;

use ark_ec::{AffineCurve, PairingEngine};
use blake2::Digest;
use manta_trusted_setup::{
    ceremony::{
        queue::{Identifier, Priority},
        server::Server,
        signature::{ed_dalek, ed_dalek::Ed25519, HasPublicKey},
        CeremonyError,
    },
    groth16::mpc::{Groth16Phase2, Proof, State},
    pairing::Pairing,
    util::BlakeHasher,
};
use manta_util::into_array_unchecked;
use serde::Serialize;
use std::{collections::BTreeMap, future::Future};
use tide::{Body, Response, StatusCode};

struct Participant {
    pub public_key: ed_dalek::PublicKey,
    pub priority: usize,
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

struct Config {}

impl Pairing for Config {
    type Scalar = ark_bls12_381::Fr;
    type G1 = ark_bls12_381::G1Affine;
    type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;
    type G2 = ark_bls12_381::G2Affine;
    type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;
    type Pairing = ark_bls12_381::Bls12_381;

    #[inline]
    fn g1_prime_subgroup_generator() -> Self::G1 {
        ark_bls12_381::G1Affine::prime_subgroup_generator()
    }

    #[inline]
    fn g2_prime_subgroup_generator() -> Self::G2 {
        ark_bls12_381::G2Affine::prime_subgroup_generator()
    }
}

impl manta_trusted_setup::groth16::mpc::Configuration for Config {
    type Challenge = [u8; 64];
    type Hasher = BlakeHasher;

    #[inline]
    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge {
        let mut hasher = Self::Hasher::default();
        hasher.0.update(challenge);
        prev.serialize(&mut hasher)
            .expect("Consuming the previous state failed.");
        next.serialize(&mut hasher)
            .expect("Consuming the current state failed.");
        proof
            .serialize(&mut hasher)
            .expect("Consuming proof failed");
        into_array_unchecked(hasher.0.finalize())
    }
}
type S = Server<
    Groth16Phase2<Config>,
    Participant,
    BTreeMap<ed_dalek::PublicKey, Participant>,
    Ed25519,
    2,
>;
fn init_server() -> S {
    todo!()
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut api = tide::Server::with_state(init_server());

    api.at("/register")
        .post(|r| Server::execute(r, Server::register_participant));
    api.at("/get_state_and_challenge")
        .post(|r| Server::execute(r, Server::get_state_and_challenge));
    api.at("/update")
        .post(|r| Server::execute(r, Server::update));

    api.listen("127.0.0.1:8080").await?;

    Ok(())
}
pub enum Error {
    AlreadyQueued,
    InvalidSignature,
    CeremonyError(CeremonyError),
} // all server errors go into this enum

impl From<Error> for tide::Error {
    #[inline]
    fn from(err: Error) -> tide::Error {
        match err {
            _ => Self::from_str(
                StatusCode::InternalServerError,
                "unable to complete request",
            ),
        }
    }
}

impl From<CeremonyError> for Error {
    #[inline]
    fn from(e: CeremonyError) -> Self {
        Self::CeremonyError(e)
    }
}

// Result Type
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Generates the JSON body for the output of `f`, returning an HTTP reponse.
#[inline]
async fn into_body<R, F, Fut>(f: F) -> Result<Response, tide::Error>
where
    R: Serialize,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R>>,
{
    Ok(Body::from_json(&f().await?)?.into())
}
