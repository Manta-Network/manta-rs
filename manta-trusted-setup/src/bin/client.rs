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

// use manta_trusted_setup::ceremony::coordinator::*;
use manta_trusted_setup::ceremony::{
    bls_server::{CeremonyPriority, Participant},
    requests::*,
    signature::ed_dalek_signatures::*,
};
// use manta_trusted_setup::ceremony::queue::*;
// use manta_trusted_setup::ceremony::CeremonyError;

#[async_std::main]
async fn main() -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();

    // Generate a keypair
    let (private_key, public_key) = test_keypair();
    // Form a registration request
    let participant = Participant {
        id: public_key,
        priority: CeremonyPriority::High,
        has_contributed: false,
    };
    let request = RegisterRequest { participant };
    // Send to server
    client
        .post("http://127.0.0.1:8080/register")
        .json(&request)
        .send()
        .await?
        .json()
        .await?; // todo: that can be compressed, I just broke apart the request to illustrate

    Ok(())
}
