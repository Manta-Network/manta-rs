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

use ark_sapling_mpc_verify::phase_two;
use manta_trusted_setup::{
    ceremony::{
        bls_server::{BlsPhase2State, CeremonyPriority, Participant, SaplingBls12Ceremony},
        requests::*,
        signature::{ed_dalek_signatures::*},
    },
    mpc::Contribute,
};

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
    let request = RegisterRequest {
        participant: participant.clone(),
    };
    // Send to server
    client
        .post("http://127.0.0.1:8080/register")
        .json(&request)
        .send()
        .await?
        .json()
        .await?;

    // Now client is in queue
    // TODO: adding to `Registry` and adding to `Queue` need to be 
    // separate events because we are populating the registry "by hand"

    // Form a request for MPC:
    let request = GetMpcRequest::<Participant, Ed25519, SaplingBls12Ceremony>::form_request(
        &participant,
        &public_key,
        &private_key,
    )
    .unwrap();
    // Send to server
    let _response = client
        .post("http://127.0.0.1:8080/get_state_and_challenge")
        .json(&request)
        .send()
        .await?
        .json::<GetMpcResponse<_, SaplingBls12Ceremony>>()
        .await?;
    println!("Received MPC State from sever");

    // Now contribute randomness
    println!("Contributing to the MPC (this may take 5 minutes -- how do we turn on rayon?)");

    // TODO: the state should come from GetMpcResponse, which isn't implemented yet, so here's a hack for testing:
    let mut state = BlsPhase2State::from(phase_two::MPCParameters::default());
    let ceremony = SaplingBls12Ceremony::default();
    let proof = ceremony.contribute(&mut state, &(), &());
    println!("Finished contribution");

    // Form a ContributeRequest
    let request = ContributeRequest::<Participant, Ed25519, SaplingBls12Ceremony>::form_request(
        &(state, proof, participant),
        &public_key,
        &private_key,
    )
    .unwrap();
    // Send to server
    client
        .post("http://127.0.0.1:8080/update")
        .json(&request)
        .send()
        .await?
        .json()
        .await?;
    println!("Sent contribution to verifier");

    Ok(())
}
