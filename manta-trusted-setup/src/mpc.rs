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

    /// Challenge Type
    type Challenge;

    /// Contribution Proof Type
    type Proof;
}

/// Contribution
pub trait Contribute: Types {
    /// Private Contribution Data
    type Contribution;

    /// Computes the next state from `state`, `challenge`, and `contribution`.
    fn contribute(
        &self,
        state: &mut Self::State,
        challenge: &Self::Challenge,
        contribution: &Self::Contribution,
    ) -> Self::Proof;
}

/// Verification
pub trait Verify: Types {
    /// Error
    type Error;

    /// Computes the challenge associated to `state` and `challenge` for the next player.
    fn challenge(&self, state: &Self::State, challenge: &Self::Challenge) -> Self::Challenge;

    /// Verifies the transformation from `last` to `next` using the `next_challenge` and `proof` as
    /// evidence for the correct update of the state. This method returns the `next` state and
    /// the next response.
    fn verify_transform(
        &self,
        last: Self::State,
        next: Self::State,
        next_challenge: Self::Challenge,
        proof: Self::Proof,
    ) -> Result<Self::State, Self::Error>;

    /// Verifies all contributions in `iter` chaining from an initial `state` and `challenge` returning the
    /// newest [`State`](Types::State) and [`Challenge`](Types::Challenge) if all the contributions
    /// in the chain had valid transitions.
    #[inline]
    fn verify_transform_all<E, I>(
        &self,
        mut state: Self::State,
        mut challenge: Self::Challenge,
        iter: I,
    ) -> Result<(Self::State, Self::Challenge), Self::Error>
    where
        E: Into<Self::Error>,
        I: IntoIterator<Item = Result<(Self::State, Self::Proof), E>>,
    {
        for item in iter {
            let (next, next_proof) = item.map_err(Into::into)?;
            let next_challenge = self.challenge(&state, &challenge);
            challenge = self.challenge(&next, &next_challenge);
            state = self.verify_transform(state, next, next_challenge, next_proof)?;
        }
        Ok((state, challenge))
    }
}
