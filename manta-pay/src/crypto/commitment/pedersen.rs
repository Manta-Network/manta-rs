// Copyright 2019-2021 Manta Network.
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

//! Pedersen Commitment Implementation

use ark_crypto_primitives::commitment::{
    pedersen::{Commitment, Window},
    CommitmentScheme as ArkCommitmentScheme,
};
use ark_ed_on_bls12_381::EdwardsProjective;
use core::borrow::Borrow;
use manta_crypto::CommitmentScheme;
use rand::RngCore;

/// Implementation of [`CommitmentScheme`]
#[derive(Clone)]
pub struct PedersenCommitment(<ArkPedersenCommitment as ArkCommitmentScheme>::Parameters);

impl PedersenCommitment {
    /// Pedersen Window Size
    pub const WINDOW_SIZE: usize = 4;

    /// Pedersen Window Count
    pub const NUM_WINDOWS: usize = 256;
}

/// Pedersen Window Parameters
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PedersenWindow;

impl Window for PedersenWindow {
    const WINDOW_SIZE: usize = PedersenCommitment::WINDOW_SIZE;
    const NUM_WINDOWS: usize = PedersenCommitment::NUM_WINDOWS;
}

/// Arkworks Pedersen Commitment
pub type ArkPedersenCommitment = Commitment<EdwardsProjective, PedersenWindow>;

impl CommitmentScheme for PedersenCommitment {
    type Randomness = <ArkPedersenCommitment as ArkCommitmentScheme>::Randomness;

    type Output = <ArkPedersenCommitment as ArkCommitmentScheme>::Output;

    #[inline]
    fn setup<R>(rng: &mut R) -> Self
    where
        R: RngCore,
    {
        Self(ArkPedersenCommitment::setup(rng).expect("As of arkworks 0.3.0, this never fails."))
    }

    #[inline]
    fn commit<I>(&self, input: I, randomness: &Self::Randomness) -> Self::Output
    where
        I: Borrow<[u8]>,
    {
        ArkPedersenCommitment::commit(&self.0, input.borrow(), randomness)
            .expect("As of arkworks 0.3.0, this never fails.")
    }
}
