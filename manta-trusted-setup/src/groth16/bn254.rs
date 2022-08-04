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
    groth16,
    groth16::{
        kzg::{Accumulator, Configuration, Proof, Size},
        mpc::{self, Proof as MpcProof, ProvingKeyHasher, State},
    },
    mpc::Types,
    pairing::{Pairing, PairingEngineExt},
    util::{power_pairs, BlakeHasher, KZGBlakeHasher},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, Parameters};
use ark_ec::{
    models::{bn::BnParameters, ModelParameters},
    short_weierstrass_jacobian::GroupAffine,
    AffineCurve, PairingEngine, SWModelParameters,
};
use ark_ff::{field_new, PrimeField, Zero};
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::eq::EqGadget;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Read};
use ark_snark::SNARK;
use blake2::Digest;
use core::fmt::Debug;
use manta_crypto::{
    constraint::Allocate,
    eclair::alloc::mode::{Public, Secret},
    rand::{CryptoRng, OsRng, RngCore},
};
use manta_pay::crypto::constraint::arkworks::{Fp, FpVar, R1CS};
use manta_util::into_array_unchecked;
use memmap::{Mmap, MmapOptions};
use std::{fs::{File, OpenOptions}, time::Instant};


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

/// Configuration for PPoT Phase 1 over Bn254 curve.
pub struct SmallBn254;

impl Size for SmallBn254 {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;

    const G2_POWERS: usize = 1 << 16;
}

impl Pairing for SmallBn254 {
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

impl Configuration for SmallBn254 {
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

impl Types for SmallBn254 {
    type State = State<Self>;
    type Challenge = [u8; 64];
    type Proof = MpcProof<Self>;
}

impl<P> ProvingKeyHasher<P> for SmallBn254
where
    P: Pairing,
{
    type Output = [u8; 64];

    #[inline]
    fn hash(proving_key: &ProvingKey<P::Pairing>) -> Self::Output {
        let mut hasher = BlakeHasher::default();
        proving_key
            .serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl mpc::Configuration for SmallBn254 {
    type Challenge = [u8; 64];
    type Hasher = BlakeHasher;

    #[inline]
    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &MpcProof<Self>,
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

pub type SmallBn254Accumulator = Accumulator<SmallBn254>;

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
pub fn deserialize_g2_unchecked<R>(reader: &mut R) -> Result<G2Affine, PointDeserializeError>
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
pub fn calculate_mmap_position(index: usize, element_type: ElementType) -> usize {
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
    pub fn get_size(&self) -> usize {
        match self.is_g1_type() {
            true => 64,
            false => 128,
        }
    }

    /// The number of powers of elements of this type in an accumulator.
    pub fn num_powers<S>(&self) -> usize
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
    pub fn is_g1_type(&self) -> bool {
        !matches!(self, ElementType::TauG2 | ElementType::BetaG2)
    }
}

/// Reads some number of powers from tau_g1, alpha_tau_g1, or beta_tau_g1 as well as the same
/// number from tau_g2.  Checks that all points are on-curve and in-subgroup. Returns as vectors
pub fn get_g1_and_g2_powers(
    size: usize,
    element_type: ElementType,
) -> Result<(Vec<G1Affine>, Vec<G2Affine>), PointDeserializeError> {
    if (element_type == ElementType::TauG2) | (element_type == ElementType::BetaG2) {
        panic!("The element type should be in G1")
    }
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

    let mut g1_powers = Vec::<G1Affine>::new();
    let mut g2_powers = Vec::<G2Affine>::new();
    for i in 0..size {
        let position = calculate_mmap_position(i, element_type);
        let mut reader = readable_map
            .get(position..position + element_type.get_size())
            .expect("cannot read point data from file");
        g1_powers.push(match deserialize_g1_unchecked(&mut reader) {
            Ok(p) => match curve_point_checks(&p) {
                Err(e) => {
                    println!("Error {:?} occured with element {:?}", e, i);
                    return Err(e);
                }
                _ => p,
            },
            Err(e) => {
                println!("Error {:?} occured with element {:?}", e, i);
                return Err(e);
            }
        });
        let position = calculate_mmap_position(i, ElementType::TauG2);
        let mut reader = readable_map
            .get(position..position + ElementType::get_size(&ElementType::BetaG2))
            .expect("cannot read point data from file");
        g2_powers.push(match deserialize_g2_unchecked(&mut reader) {
            Ok(p) => match curve_point_checks(&p) {
                Err(e) => {
                    println!("Error {:?} occured with element {:?}", e, i);
                    return Err(e);
                }
                _ => p,
            },
            Err(e) => {
                println!("Error {:?} occured with element {:?}", e, i);
                return Err(e);
            }
        });
    }
    Ok((g1_powers, g2_powers))
}

/// Checks that a vector of G1 elements and vector of G2 elements are incrementing by the
/// same factor.
pub fn check_consistent_factor(g1: &Vec<G1Affine>, g2: &Vec<G2Affine>) -> bool {
    let g1_pair = power_pairs(g1);
    let g2_pair = power_pairs(g2);
    Bn254::same_ratio(g1_pair, g2_pair)
}

/// Extracts a subaccumulator of size `required_powers`. Specific to PPoT challenge file.
pub fn read_subaccumulator<C>(_readable_map: Mmap) -> Result<Accumulator<C>, PointDeserializeError>
where
    C: Pairing<G1 = G1Affine, G2 = G2Affine> + Size,
{
    Ok(Accumulator {
        tau_powers_g1: read_g1_powers::<C>(ElementType::TauG1)?,
        tau_powers_g2: read_g2_powers::<C>(ElementType::TauG2)?,
        alpha_tau_powers_g1: read_g1_powers::<C>(ElementType::AlphaG1)?,
        beta_tau_powers_g1: read_g1_powers::<C>(ElementType::BetaG1)?,
        beta_g2: read_g2_powers::<C>(ElementType::BetaG2)?[0],
    })
}

/// Reads appropriate number of elements of `element_type` for an accumulator of given `Size` from PPoT challenge file.
pub fn read_g1_powers<S>(
    element: ElementType,
) -> Result<Vec<GroupAffine<<Parameters as BnParameters>::G1Parameters>>, PointDeserializeError>
where
    S: Size,
{
    let size = element.num_powers::<S>();
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
pub fn read_g2_powers<S>(
    element: ElementType,
) -> Result<Vec<GroupAffine<<Parameters as BnParameters>::G2Parameters>>, PointDeserializeError>
where
    S: Size,
{
    let size = element.num_powers::<S>();
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

#[test]
pub fn deserialize_g1_unchecked_test() {
    // Try to load `./challenge` from disk.
    let mut reader = OpenOptions::new()
        .read(true)
        .open("/Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072")
        .expect("unable open `./challenge` in this directory");

    let mut hash_discard = [0u8; 64];
    assert!(64 == Read::read(&mut reader, &mut hash_discard[..]).unwrap());

    let point: G1Affine = deserialize_g1_unchecked(&mut reader).unwrap();
    assert_eq!(
        point.into_projective(),
        G1Affine::prime_subgroup_generator().into_projective(),
        "first point should be generator"
    );
    assert!(curve_point_checks(&point).is_ok())
}

#[test]
pub fn read_tau_g1_and_g2_test() {
    let num_powers = 1 << 8;
    assert!(get_g1_and_g2_powers(num_powers, ElementType::TauG1).is_ok());
    assert!(get_g1_and_g2_powers(num_powers, ElementType::AlphaG1).is_ok());
    assert!(get_g1_and_g2_powers(num_powers, ElementType::BetaG1).is_ok())
}

#[test]
pub fn check_consistent_ratios_test() {
    let num_powers = 1 << 8;
    let (g1, g2) = get_g1_and_g2_powers(num_powers, ElementType::TauG1).unwrap();
    assert!(check_consistent_factor(&g1, &g2));
    let (g1, g2) = get_g1_and_g2_powers(num_powers, ElementType::AlphaG1).unwrap();
    assert!(check_consistent_factor(&g1, &g2));
    let (g1, g2) = get_g1_and_g2_powers(num_powers, ElementType::BetaG1).unwrap();
    assert!(check_consistent_factor(&g1, &g2));
}

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

    let acc = read_subaccumulator::<SmallBn254>(readable_map).unwrap();
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

/// Generates a dummy R1CS circuit.
#[inline]
fn dummy_circuit(cs: &mut R1CS<Fr>) {
    let a = Fp(field_new!(Fr, "2")).as_known::<Secret, FpVar<_>>(cs);
    let b = Fp(field_new!(Fr, "3")).as_known::<Secret, FpVar<_>>(cs);
    let c = &a * &b;
    let d = Fp(field_new!(Fr, "6")).as_known::<Public, FpVar<_>>(cs);
    c.enforce_equal(&d)
        .expect("enforce_equal is not allowed to fail");
}

/// Generates our `Reclaim` circuit with unknown variables
fn reclaim_circuit() -> R1CS<Fr> {
    use crate::util::Sample;
    use manta_accounting::transfer::Transfer;
    use manta_crypto::{
        accumulator::{Accumulator, Model},
        merkle_tree::forest::MerkleForest,
        rand::{Rand, SeedableRng},
    };
    use manta_pay::{
        config::{FullParameters, Reclaim},
        test::payment::UtxoAccumulator,
    };
    use rand_chacha::ChaCha20Rng;

    // use chacha

    // 2. Specialize the final Accumulator to phase 2 parameters, write these to transcript (?)
    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    let parameters = rng.gen();

    Reclaim::unknown_constraints(FullParameters::new(
        &parameters,
        <MerkleForest<_, _> as Accumulator>::model(&utxo_accumulator),
    ))
}

/// Generates our `Reclaim` circuit with known variables
fn reclaim_circuit_known() -> R1CS<Fr> {
    use crate::util::Sample;
    use manta_accounting::transfer::Transfer;
    use manta_accounting::transfer::test::TransferDistribution;
    use manta_crypto::{
        accumulator::{Accumulator, Model},
        merkle_tree::forest::MerkleForest,
        rand::{Rand, SeedableRng},
    };
    use manta_pay::{
        config::{FullParameters, Reclaim},
        test::payment::UtxoAccumulator,
    };
    use rand_chacha::ChaCha20Rng;

    // 2. Specialize the final Accumulator to phase 2 parameters, write these to transcript (?)
    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let mut utxo_accumulator = UtxoAccumulator::new(rng.gen());
    // let sample = Reclaim::sample(
    //     TransferDistribution {
    //         parameters: &parameters,
    //         utxo_accumulator: &mut utxo_accumulator,
    //     },
    //     &mut rng,
    // );
    // let sample = manta_accounting::transfer::Transfer:

    // let parameters = rng.gen();

    todo!()
}

/// Proves and verifies a R1CS circuit with proving key `pk` and a random number generator `rng`.
#[inline]
pub fn prove_and_verify_circuit<P, R>(pk: ProvingKey<P>, cs: R1CS<Fr>, mut rng: &mut R)
where
    P: PairingEngine<Fr = Fr>,
    R: CryptoRng + RngCore + ?Sized,
{
    assert!(
        Groth16::verify(
            &pk.vk,
            &[field_new!(Fr, "6")],
            &Groth16::prove(&pk, cs, &mut rng).unwrap()
        )
        .unwrap(),
        "Verify proof should succeed."
    );
}

#[test]
pub fn bn254_end_to_end_test() {
    use crate::{
        groth16::mpc::{self, contribute, initialize, verify_transform, verify_transform_all},
        mpc::Transcript,
    };
    println!("Reading subaccumulator from file");
    let now = Instant::now();
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

    let acc = read_subaccumulator::<SmallBn254>(readable_map).unwrap();
    println!("Finished reading subacc. in {:?}", now.elapsed());

    println!("Specializing acc. to phase 2");
    let now = Instant::now();
    let mut rng = OsRng;
    let cs = reclaim_circuit();
    let mut state = initialize(acc, cs).unwrap();
    println!("Finished making pk in {:?}", now.elapsed());

    println!("Contributing to phase 2 params");
    // Contribute and verify
    let mut transcript = Transcript::<SmallBn254> {
        initial_challenge: <SmallBn254 as mpc::ProvingKeyHasher<SmallBn254>>::hash(&state),
        initial_state: state.clone(),
        rounds: Vec::new(),
    };
    let hasher = <SmallBn254 as mpc::Configuration>::Hasher::default();
    let (mut prev_state, mut proof): (State<SmallBn254>, groth16::mpc::Proof<SmallBn254>);
    let mut challenge = transcript.initial_challenge;
    for _ in 0..5 {
        let now = Instant::now();
        prev_state = state.clone();
        proof = contribute::<SmallBn254, _>(&hasher, &challenge, &mut state, &mut rng).unwrap();
        (challenge, state) = verify_transform(&challenge, prev_state, state, proof.clone())
            .expect("Verify transform failed");
        transcript.rounds.push((state.clone(), proof));
        println!("Performed a contribution in {:?}", now.elapsed());
    }
    println!("Verifying 5 contributions");
    let now = Instant::now();
    verify_transform_all(
        transcript.initial_challenge,
        transcript.initial_state,
        transcript.rounds,
    )
    .expect("Verifying all transformations failed.");
    println!("Verified phase 2 contributions in {:?}", now.elapsed());

    // Write pk to file for quicker testing
    let _f = File::create("phase2_reclaim_pk").unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .open("phase2_reclaim_pk")
        .expect("unable to create parameter file in this directory");
    CanonicalSerialize::serialize_uncompressed(&state, &mut file).unwrap();

    // Check that this was written correctly:
    let mut reader = OpenOptions::new()
        .read(true)
        .open("phase2_reclaim_pk")
        .expect("file not found");
    let pk: ProvingKey<Bn254> = CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();
    assert_eq!(pk, state)

    // Check that it works as a proving key
    // let cs = reclaim_circuit();
    // prove_and_verify_circuit(state, cs, &mut rng);

}

#[test]
pub fn bn254_pk_read_and_check_time() {
    println!("Reading pk from file");
    let now = Instant::now();
    let mut reader = OpenOptions::new()
        .read(true)
        .open("phase2_reclaim_pk")
        .expect("file not found");
    let pk: ProvingKey<Bn254> = CanonicalDeserialize::deserialize_uncompressed(&mut reader).unwrap();
    println!("Read and checked pk in {:?}", now.elapsed());
}