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

//! Groth16 MPC (Phase 2) for Bn254 Backend

use crate::{
    groth16::{
        mpc::{Configuration, Proof, ProvingKeyHasher, State},
        ppot::kzg::PerpetualPowersOfTauCeremony,
    },
    mpc::Types,
    util::BlakeHasher,
};
use ark_groth16::ProvingKey;
use blake2::Digest;
use manta_crypto::arkworks::{pairing::Pairing, serialize::CanonicalSerialize};
use manta_util::into_array_unchecked;

impl<S, const POWERS: usize> Configuration for PerpetualPowersOfTauCeremony<S, POWERS> {
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

impl<S, const POWERS: usize> Types for PerpetualPowersOfTauCeremony<S, POWERS> {
    type State = State<Self>;
    type Challenge = [u8; 64];
    type Proof = Proof<Self>;
}

impl<S, const POWERS: usize> ProvingKeyHasher<Self> for PerpetualPowersOfTauCeremony<S, POWERS> {
    type Output = [u8; 64];

    #[inline]
    fn hash(proving_key: &ProvingKey<<Self as Pairing>::Pairing>) -> Self::Output {
        let mut hasher = BlakeHasher::default();
        proving_key
            .serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");
        into_array_unchecked(hasher.0.finalize())
    }
}
