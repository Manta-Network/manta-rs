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

//! Utility functions for Perpetual Powers of Tau

use crate::{
    groth16::{
        bn254::manta_pay::MantaPaySetupCeremony,
        kzg::{Accumulator, Configuration as KzgConfiguration, Proof as KzgProof, Size},
    },
    util::{BlakeHasher, KZGBlakeHasher},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, Parameters};
use manta_crypto::arkworks::{
    ec::{
        models::{bn::BnParameters, ModelParameters},
    short_weierstrass_jacobian::GroupAffine,
    AffineCurve, PairingEngine, SWModelParameters,
    },
    ff::{PrimeField, Zero},
    pairing::Pairing,
};
use ark_serialize::{CanonicalSerialize, Read};
use blake2::Digest;
use manta_util::into_array_unchecked;
use memmap::{Mmap, MmapOptions};
use std::fs::OpenOptions;

/// Configuration of the Perpetual Powers of Tau ceremony
pub struct PpotCeremony;

impl Size for PpotCeremony {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;

    const G2_POWERS: usize = 1 << 28;
}

impl Pairing for PpotCeremony {
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

impl KzgConfiguration for PpotCeremony {
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
        proof: &KzgProof<Self>,
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

/// Accumulator of the PPoT ceremony
pub type PpotAccumulator = Accumulator<PpotCeremony>;

type BaseFieldG1Type = <<Parameters as BnParameters>::G1Parameters as ModelParameters>::BaseField;
type BaseFieldG2Type = <<Parameters as BnParameters>::G2Parameters as ModelParameters>::BaseField;

// Only makes sense for this to be deserialization from uncompressed bytes since
// deserializing from compressed implies at least doing an on-curve check
#[inline]
fn deserialize_g1_unchecked<R>(reader: &mut R) -> Result<G1Affine, PointDeserializeError>
where
    R: Read,
{
    let mut copy = [0u8; 64];
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
        if copy[0] & (1 << 7) != 0 {
            // Since this representation is uncompressed the flag should be set to 0
            return Err(PointDeserializeError::ExtraYCoordinate);
        }

        // Now unset the first two bits
        copy[0] &= 0x3f;

        // Now we can deserialize the remaining bytes to field elements
        let x = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..32]);
        let y = BaseFieldG1Type::from_be_bytes_mod_order(&copy[32..]);

        Ok(G1Affine::new(x, y, false))
    }
}

// Only makes sense for this to be deserialization from uncompressed bytes since
// deserializing from compressed implies at least doing an on-curve check
#[inline]
fn deserialize_g2_unchecked<R>(reader: &mut R) -> Result<G2Affine, PointDeserializeError>
where
    R: Read,
{
    let mut copy = [0u8; 128];
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
            Ok(G2Affine::zero())
        } else {
            // Then there are unexpected bits
            Err(PointDeserializeError::PointAtInfinity)
        }
    } else {
        // Check y-coordinate flag // TODO : The PPOT code doesn't seem to do this...
        if copy[0] & (1 << 7) != 0 {
            // Since this representation is uncompressed the flag should be set to 0
            return Err(PointDeserializeError::ExtraYCoordinate);
        }

        // Now unset the first two bits
        copy[0] &= 0x3f;

        // Now we can deserialize the remaining bytes to field elements
        let x_c1 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..32]);
        let x_c0 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[32..64]);
        let y_c1 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[64..96]);
        let y_c0 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[96..128]);
        // Recall BaseFieldG2 is a quadratic ext'n of BaseFieldG1
        let x = BaseFieldG2Type::new(x_c0, x_c1);
        let y = BaseFieldG2Type::new(y_c0, y_c1);

        Ok(G2Affine::new(x, y, false))
    }
}

/// Checks that the purported GroupAffine element is on-curve and in-subgroup.
#[inline]
fn curve_point_checks<P>(g1: &GroupAffine<P>) -> Result<(), PointDeserializeError>
where
    P: SWModelParameters,
{
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

/// Calculates position in the mmap of specific parts of accumulator.
/// TODO : This is currently specialized to PPoT Bn254 setup
fn calculate_mmap_position(index: usize, element_type: ElementType) -> usize {
    // These are entered by hand from the Bn254 parameters of PPoT
    const G1_UNCOMPRESSED_BYTE_SIZE: usize = 64;
    const G2_UNCOMPRESSED_BYTE_SIZE: usize = 128;
    const REQUIRED_POWER: usize = 28;
    const TAU_POWERS_LENGTH: usize = 1 << REQUIRED_POWER;
    const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;
    const HASH_SIZE: usize = 64;

    let g1_size = G1_UNCOMPRESSED_BYTE_SIZE;
    let g2_size = G2_UNCOMPRESSED_BYTE_SIZE;
    let required_tau_g1_power = TAU_POWERS_G1_LENGTH;
    let required_power = TAU_POWERS_LENGTH;

    let position = match element_type {
        ElementType::TauG1 => {
            let mut position = 0;
            position += g1_size * index;
            // assert!(index < TAU_POWERS_G1_LENGTH, format!("Index of TauG1 element written must not exceed {:?}, while it's {:?}", TAU_POWERS_G1_LENGTH, index));
            assert!(index < TAU_POWERS_G1_LENGTH);

            position
        }
        ElementType::TauG2 => {
            let mut position = 0;
            position += g1_size * required_tau_g1_power;
            // assert!(index < TAU_POWERS_LENGTH, format!("Index of TauG2 element written must not exceed {}, while it's {}", TAU_POWERS_LENGTH, index));
            assert!(index < TAU_POWERS_LENGTH);
            position += g2_size * index;

            position
        }
        ElementType::AlphaG1 => {
            let mut position = 0;
            position += g1_size * required_tau_g1_power;
            position += g2_size * required_power;
            // assert!(index < TAU_POWERS_LENGTH, format!("Index of AlphaG1 element written must not exceed {}, while it's {}", TAU_POWERS_LENGTH, index));
            assert!(index < TAU_POWERS_LENGTH);
            position += g1_size * index;

            position
        }
        ElementType::BetaG1 => {
            let mut position = 0;
            position += g1_size * required_tau_g1_power;
            position += g2_size * required_power;
            position += g1_size * required_power;
            // assert!(index < TAU_POWERS_LENGTH, format!("Index of AlphaG1 element written must not exceed {}, while it's {}", TAU_POWERS_LENGTH, index));
            assert!(index < TAU_POWERS_LENGTH);
            position += g1_size * index;

            position
        }
        ElementType::BetaG2 => {
            let mut position = 0;
            position += g1_size * required_tau_g1_power;
            position += g2_size * required_power;
            position += g1_size * required_power;
            position += g1_size * required_power;

            position
        }
    };

    position + HASH_SIZE
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ElementType {
    TauG1,
    TauG2,
    AlphaG1,
    BetaG1,
    BetaG2,
}

impl ElementType {
    /// This function is specific to the PPoT Bn254 setup
    fn get_size(&self) -> usize {
        match self.is_g1_type() {
            true => 64,
            false => 128,
        }
    }

    /// The number of powers of elements of this type in an accumulator.
    fn num_powers<S>(&self) -> usize
    where
        S: Size,
    {
        match self {
            ElementType::BetaG2 => 1,
            ElementType::TauG1 => S::G1_POWERS,
            _ => S::G2_POWERS,
        }
    }

    /// Element is a point on the G1 curve
    fn is_g1_type(&self) -> bool {
        !matches!(self, ElementType::TauG2 | ElementType::BetaG2)
    }
}

/// Reads appropriate number of elements of `element_type` for an accumulator of given `Size` from PPoT challenge file.
#[inline]
pub fn read_g1_powers<S>(
    readable_map: &Mmap,
    element: ElementType,
) -> Result<Vec<GroupAffine<<Parameters as BnParameters>::G1Parameters>>, PointDeserializeError>
where
    S: Size,
{
    let size = element.num_powers::<S>();
    let mut powers = Vec::new();
    let mut start_position = calculate_mmap_position(0, element);
    let mut end_position = start_position + element.get_size();
    for _ in 0..size {
        let mut reader = readable_map
            .get(start_position..end_position)
            .expect("cannot read point data from file");
        if element.is_g1_type() {
            let point = deserialize_g1_unchecked(&mut reader)?;
            curve_point_checks(&point)?;
            powers.push(point);
        } else {
            panic!("Expected G1 curve points")
        }
        start_position = end_position;
        end_position += element.get_size();
    }

    Ok(powers)
}

/// Reads `size` many elements of `element_type` from PPoT challenge file.
#[inline]
pub fn read_g2_powers<S>(
    readable_map: &Mmap,
    element: ElementType,
) -> Result<Vec<GroupAffine<<Parameters as BnParameters>::G2Parameters>>, PointDeserializeError>
where
    S: Size,
{
    let size = element.num_powers::<S>();
    let mut powers = Vec::new();
    let mut start_position = calculate_mmap_position(0, element);
    let mut end_position = start_position + element.get_size();
    for _ in 0..size {
        let mut reader = readable_map
            .get(start_position..end_position)
            .expect("cannot read point data from file");
        if !element.is_g1_type() {
            let point = deserialize_g2_unchecked(&mut reader)?;
            curve_point_checks(&point)?;
            powers.push(point);
        } else {
            panic!("Expected G2 curve points")
        }
        start_position = end_position;
        end_position += element.get_size();
    }

    Ok(powers)
}

/// Extracts a subaccumulator of size `required_powers`. Specific to PPoT challenge file.
#[inline]
pub fn read_subaccumulator<C>(readable_map: &Mmap) -> Result<Accumulator<C>, PointDeserializeError>
where
    C: Pairing<G1 = G1Affine, G2 = G2Affine> + Size,
{
    Ok(Accumulator {
        tau_powers_g1: read_g1_powers::<C>(readable_map, ElementType::TauG1)?,
        tau_powers_g2: read_g2_powers::<C>(readable_map, ElementType::TauG2)?,
        alpha_tau_powers_g1: read_g1_powers::<C>(readable_map, ElementType::AlphaG1)?,
        beta_tau_powers_g1: read_g1_powers::<C>(readable_map, ElementType::BetaG1)?,
        beta_g2: read_g2_powers::<C>(readable_map, ElementType::BetaG2)?[0],
    })
}

/// Checks that a vector of G1 elements and vector of G2 elements are incrementing by the
/// same factor.
#[inline]
fn check_consistent_factor(g1: &Vec<G1Affine>, g2: &Vec<G2Affine>) -> bool {
    use crate::util::power_pairs;
    use manta_crypto::arkworks::pairing::PairingEngineExt;

    let g1_pair = power_pairs(g1);
    let g2_pair = power_pairs(g2);
    Bn254::same_ratio(g1_pair, g2_pair)
}

/// Reads a subaccumulator from the PPoT file and does some basic
/// sanity checks on the powers. For MantaPay circuit (size 1 << 16)
/// this takes about 10 mins.
#[test]
pub fn read_subaccumulator_test() {
    // Try to load `./challenge` from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open("/Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072")
        .expect("unable open `./challenge` in this directory");
    // Make a memory map
    let readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    // These check that vectors of G1 elements and the vector `tau_powers_g2`
    // are incrementing by the same (unknown) factor `tau`.
    let acc = read_subaccumulator::<MantaPaySetupCeremony>(&readable_map).unwrap();
    assert!(check_consistent_factor(
        &acc.tau_powers_g1,
        &acc.tau_powers_g2
    ));
    assert!(check_consistent_factor(
        &acc.alpha_tau_powers_g1,
        &acc.tau_powers_g2
    ));
    assert!(check_consistent_factor(
        &acc.beta_tau_powers_g1,
        &acc.tau_powers_g2
    ));
}
