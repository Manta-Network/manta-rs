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

//! Bn254 Backend for Groth16 Trusted Setup

use crate::{
    groth16::kzg::{Accumulator, Configuration, Proof, Size},
    pairing::Pairing,
    util::{BlakeHasher, KZGBlakeHasher},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, Parameters};
use ark_ec::{
    models::{bn::BnParameters, ModelParameters},
    AffineCurve, PairingEngine,
};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use blake2::Digest;
use core::fmt::{self, Debug};
use manta_util::into_array_unchecked;
use std::io::Read;
use std::fs::OpenOptions;

/// Configuration for PPoT Phase 1 over Bn254 curve.
pub struct PpotBn254;

impl Size for PpotBn254 {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;

    const G2_POWERS: usize = 1 << 28;
}

impl Pairing for PpotBn254 {
    type Scalar = Fr;

    type G1 = G1Affine;

    type G1Prepared = <Bn254 as PairingEngine>::G1Prepared;

    type G2 = G2Affine;

    type G2Prepared = <Bn254 as PairingEngine>::G2Prepared;

    type Pairing = Bn254;

    fn g1_prime_subgroup_generator() -> Self::G1 {
        G1Affine::prime_subgroup_generator()
    }

    fn g2_prime_subgroup_generator() -> Self::G2 {
        G2Affine::prime_subgroup_generator()
    }
}

impl Configuration for PpotBn254 {
    type DomainTag = u8;
    type Challenge = [u8; 64];
    type Response = [u8; 64];
    type HashToGroup = KZGBlakeHasher<Self>;

    const TAU_DOMAIN_TAG: Self::DomainTag = 0;
    const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
    const BETA_DOMAIN_TAG: Self::DomainTag = 2;

    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
        Self::HashToGroup { domain_tag }
    }

    fn response(
        state: &Accumulator<Self>,
        challenge: &Self::Challenge,
        proof: &Proof<Self>,
    ) -> Self::Response {
        let mut hasher = BlakeHasher::default();
        for item in &state.tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.tau_powers_g2 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.alpha_tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.beta_tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        state.beta_g2.serialize_uncompressed(&mut hasher).unwrap();
        hasher.0.update(&challenge);
        proof
            .tau
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of tau failed.");
        proof
            .alpha
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of alpha failed.");
        proof
            .beta
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of beta failed.");
        into_array_unchecked(hasher.0.finalize())
    }
}

pub type Bn254Accumulator = Accumulator<PpotBn254>;

/// Read from a Perpetual Powers of Tau challenge file.
/// TODO: Not sure this is actually useful. I think we only want to
/// read portions of that challenge file to construct our own smaller accumulator.
pub fn read_accumulator_from_ppot_file() -> Bn254Accumulator {
    todo!()
}

type BaseFieldG1Type = <<Parameters as BnParameters>::G1Parameters as ModelParameters>::BaseField;
type BaseFieldG2Type = <<Parameters as BnParameters>::G2Parameters as ModelParameters>::BaseField;

// Only makes sense for this to be deserialization from uncompressed bytes since
// deserializing from compressed implies at least doing an on-curve check
#[inline]
fn deserialize_g1_unchecked<R>(reader: &mut R) -> Result<G1Affine, PointDeserializeError>
where
    R: Read,
{
    let mut copy = [0u8; 96];
    let _ = reader.read(&mut copy); // should I deal with the number of bytes read output?

    // Check the compression flag
    if copy[0] & (1 << 7) != 0 {
        // If that bit is non-zero then the reader contains a compressed representation
        return Err(PointDeserializeError::ExpectedUncompressed);
    }

    // Check the point at infinity flag
    if copy[0] & (1 << 6) != 0 {
        // Then this is the point at infinity, so the rest of the serialization
        // should consist of zeros after we mask away the first two bits.
        copy[0] &= 0x3f;

        if copy.iter().all(|b| *b == 0) {
            Ok(G1Affine::zero())
        } else {
            // Then there are unexpected bits
            Err(PointDeserializeError::PointAtInfinity)
        }
    } else {
        // Check y-coordinate flag
        if copy[0] & (1 << 5) != 0 {
            // Since this representation is uncompressed the flag should be set to 0
            return Err(PointDeserializeError::ExtraYCoordinate);
        }

        // Now unset the first three bits
        copy[0] &= 0x1f;

        // Now we can deserialize the remaining bytes to field elements
        let x = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..48]);
        let y = BaseFieldG1Type::from_be_bytes_mod_order(&copy[48..]);

        Ok(G1Affine::new(x, y, false))
    }
}

#[inline]
        fn curve_point_checks_g1(g1: &G1Affine) -> Result<(), PointDeserializeError> {
            if !g1.is_on_curve() {
                return Err(PointDeserializeError::NotOnCurve);
            } else if !g1.is_in_correct_subgroup_assuming_on_curve() {
                return Err(PointDeserializeError::NotInSubgroup);
            }
            Ok(())
        }

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub enum PointDeserializeError {
        CompressionFlag,
        ExpectedCompressed,
        ExpectedUncompressed,
        PointAtInfinity,
        ExtraYCoordinate,
        NotOnCurve,
        NotInSubgroup,
    }

    // TODO: What was the below code for ? 

    // impl std::fmt::Display for PointDeserializeError {
    //     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    //         Debug::fmt(&self, f) // ? Is this an okay thing to do ?
    //     }
    // }

    // impl std::error::Error for PointDeserializeError {}

#[test]
pub fn dummy_test() {
    println!("Hello");
}

#[test]
pub fn deserialize_g1_unchecked_test() {
    // Try to load `./challenge` from disk.
    let mut reader = OpenOptions::new()
                            .read(true)
                            .open("/Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072").expect("unable open `./challenge` in this directory");

    let mut hash_discard = [0u8; 64];
    assert!(64 == Read::read(&mut reader, &mut hash_discard[..]).unwrap());

    let point: G1Affine = deserialize_g1_unchecked(&mut reader).unwrap();
    println!("The first point we get is {:?}", point);
    println!("The G1 generator is {:?}", G1Affine::prime_subgroup_generator());
    // assert!(curve_point_checks_g1(&point).is_ok())
    println!("The curve point check yields {:?}", curve_point_checks_g1(&point));
}