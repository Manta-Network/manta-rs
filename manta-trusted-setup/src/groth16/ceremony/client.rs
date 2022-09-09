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

//! Trusted Setup Client

use crate::groth16::{
    ceremony::{
        message::{ContributeRequest, QueryRequest, Signed},
        signature::Nonce,
        Ceremony, CeremonyError, Participant,
    },
    mpc::{contribute, State},
};
use console::style;
use manta_crypto::{dalek::ed25519::Ed25519, rand::OsRng};
use manta_util::BoxArray;

/// Client
pub struct Client<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// Identifier
    identifier: C::Identifier,

    /// Current Nonce
    nonce: C::Nonce,

    /// Signing Key
    signing_key: C::SigningKey,
}

impl<C, const CIRCUIT_COUNT: usize> Client<C, CIRCUIT_COUNT>
where
    C: Ceremony,
{
    /// Builds a new [`Client`] with `participant` and `private_key`.
    #[inline]
    pub fn new(identifier: C::Identifier, nonce: C::Nonce, signing_key: C::SigningKey) -> Self {
        Self {
            identifier,
            nonce,
            signing_key,
        }
    }

    /// Queries the server state.
    #[inline]
    pub fn query(&mut self) -> Result<Signed<QueryRequest, C>, CeremonyError<C>>
    where
        C::Nonce: Clone,
    {
        let signed_message = Signed::new(
            QueryRequest,
            &self.nonce,
            &self.signing_key,
            self.identifier.clone(),
        )?;
        self.nonce.increment();
        Ok(signed_message)
    }

    /// Contributes to the state on the server.
    #[inline]
    pub fn contribute(
        &mut self,
        hasher: &C::Hasher,
        challenge: &BoxArray<C::Challenge, CIRCUIT_COUNT>,
        mut state: BoxArray<State<C>, CIRCUIT_COUNT>,
    ) -> Result<Signed<ContributeRequest<C, CIRCUIT_COUNT>, C>, CeremonyError<C>>
    where
        C::Nonce: Clone,
    {
        let circuit_name = ["ToPrivate", "PrivateTransfer", "ToPublic"];
        let mut rng = OsRng;
        let mut proofs = Vec::new();
        for i in 0..CIRCUIT_COUNT {
            println!(
                "{} Contributing to {} Circuits...",
                style(format!("[{}/9]", i + 5)).bold().dim(),
                circuit_name[i],
            );
            match contribute(hasher, &challenge[i], &mut state[i], &mut rng) {
                Some(proof) => proofs.push(proof),
                None => return Err(CeremonyError::Unexpected),
            }
        }
        println!(
            "{} Waiting for Confirmation from Server... Estimated Waiting Time: {} minutes.",
            style("[8/9]").bold().dim(),
            style("3").bold().blue(),
        );
        let signed_message = Signed::new(
            ContributeRequest((state, BoxArray::from_vec(proofs))),
            &self.nonce,
            &self.signing_key,
            self.identifier.clone(),
        );
        self.nonce.increment();
        signed_message
    }
}
