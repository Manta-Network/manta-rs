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

//! MPC Primitives

///
pub trait Contribute {
    ///
    type Accumulator;

    ///
    type Contribution;

    ///
    type PublicKey;

    ///
    type Challenge;

    ///
    type Response;

    ///
    fn contribute(
        &self,
        accumulator: &Self::Accumulator,
        challenge: &Self::Challenge,
        contribution: &Self::Contribution,
    ) -> (Self::Response, Self::PublicKey, Self::Accumulator);
}

///
pub trait Verify {
    /// Accumulator
    type Accumulator;

    /// Contribution Public Key
    type PublicKey;

    /// Challenge
    type Challenge;

    /// Response
    type Response;

    /// Error
    type Error;

    /// Computes the challenge associated to `last` and `last_response` for the next player.
    fn challenge(
        &self,
        last: &Self::Accumulator,
        last_response: &Self::Response,
    ) -> Self::Challenge;

    /// Computes the response from `next` and `next_key` to the `challenge` presented by the
    /// previous state.
    fn response(
        &self,
        next: &Self::Accumulator,
        next_key: &Self::PublicKey,
        challenge: Self::Challenge,
    ) -> Self::Response;

    /// Verifies the transformation from `last` to `next` using the `next_key` and `next_response`
    /// as evidence for the correct update of the state. This method returns the `next` accumulator
    /// and `next_response`.
    fn verify(
        &self,
        last: Self::Accumulator,
        next: Self::Accumulator,
        next_key: Self::PublicKey,
        next_response: Self::Challenge,
    ) -> Result<(Self::Accumulator, Self::Response), Self::Error>;

    /// Verifies all accumulator contributions in `iter` chaining from `last` and `last_response`
    /// returning the newest [`Accumulator`](Self::Accumulator) and [`Response`](Self::Response) if
    /// all the contributions in the chain had valid transitions.
    #[inline]
    fn verify_all<E, I>(
        &self,
        mut last: Self::Accumulator,
        mut last_response: Self::Response,
        iter: I,
    ) -> Result<(Self::Accumulator, Self::Response), Self::Error>
    where
        E: Into<Self::Error>,
        I: IntoIterator<Item = Result<(Self::Accumulator, Self::PublicKey), E>>,
    {
        for item in iter {
            let (next, next_key) = item.map_err(Into::into)?;
            let next_challenge = self.challenge(&next, &last_response);
            (last, last_response) = self.verify(last, next, next_key, next_challenge)?;
        }
        Ok((last, last_response))
    }
}
