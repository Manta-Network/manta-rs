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

//! Secure Multi-Party Computation Primitives

/// Secure Multi-Party Computation Types
pub trait Types {
    /// State Type
    type State;

    /// Contribution Proof Type
    type Proof;

    /// Challenge Type
    type Challenge;

    /// Response Type
    type Response;
}

/// Contribution
pub trait Contribute: Types {
    /// Private Contribution Data
    type Contribution;

    /// Comptues the next state from `state`, `challenge`, and `contribution`.
    fn contribute(
        &self,
        state: &Self::State,
        challenge: &Self::Challenge,
        contribution: &Self::Contribution,
    ) -> (Self::State, Self::Response, Self::Proof);
}

/// Verification
pub trait Verify: Types {
    /// Error
    type Error;

    /// Computes the challenge associated to `last` and `last_response` for the next player.
    fn challenge(&self, last: &Self::State, last_response: &Self::Response) -> Self::Challenge;

    /// Computes the response from `next` and `next_proof` to the `challenge` presented by the
    /// previous state.
    fn response(
        &self,
        next: &Self::State,
        next_proof: &Self::Proof,
        challenge: Self::Challenge,
    ) -> Self::Response;

    /// Verifies the transformation from `last` to `next` using the `next_proof` and `next_response`
    /// as evidence for the correct update of the state. This method returns the `next` state
    /// and `next_response`.
    fn verify(
        &self,
        last: Self::State,
        next: Self::State,
        next_proof: Self::Proof,
        next_response: Self::Challenge,
    ) -> Result<(Self::State, Self::Response), Self::Error>;

    /// Verifies all contributions in `iter` chaining from `last` and `last_response` returning the
    /// newest [`State`](Self::State) and [`Response`](Self::Response) if all the contributions in
    /// the chain had valid transitions.
    #[inline]
    fn verify_all<E, I>(
        &self,
        mut last: Self::State,
        mut last_response: Self::Response,
        iter: I,
    ) -> Result<(Self::State, Self::Response), Self::Error>
    where
        E: Into<Self::Error>,
        I: IntoIterator<Item = Result<(Self::State, Self::Proof), E>>,
    {
        for item in iter {
            let (next, next_proof) = item.map_err(Into::into)?;
            let next_challenge = self.challenge(&next, &last_response);
            (last, last_response) = self.verify(last, next, next_proof, next_challenge)?;
        }
        Ok((last, last_response))
    }
}
