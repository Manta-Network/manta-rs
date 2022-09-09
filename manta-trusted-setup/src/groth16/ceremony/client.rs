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

use crate::groth16::ceremony::{signature::Nonce, Ceremony, Participant};
use manta_crypto::dalek::ed25519::Ed25519;

use super::{
    message::{QueryRequest, Signed},
    CeremonyError,
};

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
}
