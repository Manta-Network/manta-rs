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

use alloc::vec::Vec;
use core::fmt::Debug;
use manta_crypto::rand::{CryptoRng, RngCore};

/// Secure Multi-Party Computation Types
pub trait Types {
    /// State Type
    type State: Clone;

    /// Challenge Type
    type Challenge: Clone;

    /// Contribution Proof Type
    type Proof: Clone;
}

/// Contribution
pub trait Contribute: Types {
    /// Hasher Type
    type Hasher;

    /// Computes the next state from `state`, `challenge`, and `contribution`.
    fn contribute<R>(
        hasher: &Self::Hasher,
        challenge: &Self::Challenge,
        state: &mut Self::State,
        rng: &mut R,
    ) -> Option<Self::Proof>
    where
        R: CryptoRng + RngCore + ?Sized;
}

/// Verification
pub trait Verify: Types {
    /// Verification Error Type
    type Error: Debug;

    /// Verifies the transformation from `last` to `next` using the `challenge` and `proof` as
    /// evidence for the correct update of the state. This method returns the `next` state and
    /// the next response.
    fn verify_transform(
        challenge: &Self::Challenge,
        last: &Self::State,
        next: Self::State,
        proof: &Self::Proof,
    ) -> Result<(Self::Challenge, Self::State), Self::Error>;

    /// Verifies all contributions in `iter` chaining from an initial `state` and `challenge` returning the
    /// newest [`State`](Types::State) and [`Challenge`](Types::Challenge) if all the contributions
    /// in the chain had valid transitions.
    #[inline]
    fn verify_transform_all<E, I>(
        mut challenge: Self::Challenge,
        mut state: Self::State,
        iter: I,
    ) -> Result<(Self::Challenge, Self::State), Self::Error>
    where
        E: Into<Self::Error>,
        I: IntoIterator<Item = (Self::State, Self::Proof)>,
    {
        for item in iter {
            (challenge, state) = Self::verify_transform(&challenge, &state, item.0, &item.1)?;
        }
        Ok((challenge, state))
    }
}

/// MPC Transcript
pub struct Transcript<T>
where
    T: Types,
{
    /// Initial Challenge
    pub initial_challenge: T::Challenge,

    /// Initial State
    pub initial_state: T::State,

    /// Rounds
    pub rounds: Vec<(T::State, T::Proof)>,
}
