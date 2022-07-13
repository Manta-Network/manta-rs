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

//! Groth16 Trusted Setup Phase 1

use crate::util::HasDistribution;
use ark_ec::{
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_std::UniformRand;
use manta_crypto::rand::{CryptoRng, RngCore, Sample};

use super::kzg::{Pairing, Size};

/// TODO
pub struct TrustedSetupPhaseOne;

impl Size for TrustedSetupPhaseOne {
    // TODO: change this
    const G1_POWERS: usize = 180;

    // TODO: change this
    const G2_POWERS: usize = 180;
}

impl HasDistribution for TrustedSetupPhaseOne {
    type Distribution = ();
}

impl Pairing for TrustedSetupPhaseOne {
    type Scalar = ark_bls12_381::Fr;

    type G1 = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Affine;

    type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;

    type G2 = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Affine;

    type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;

    type Pairing = ark_bls12_381::Bls12_381;

    fn sample_g1_affine<R>(rng: &mut R) -> Self::G1
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective::rand(rng).into_affine()
    }

    fn sample_g2_affine<R>(rng: &mut R) -> Self::G2
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        <ark_bls12_381::Bls12_381 as PairingEngine>::G2Projective::rand(rng).into_affine()
    }

    fn g1_prime_subgroup_generator() -> Self::G1 {
        Self::G1::prime_subgroup_generator()
    }

    fn g2_prime_subgroup_generator() -> Self::G2 {
        Self::G2::prime_subgroup_generator()
    }
}
