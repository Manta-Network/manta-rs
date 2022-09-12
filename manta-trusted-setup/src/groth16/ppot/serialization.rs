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

//! Serialization utilities for Perpetual Powers of Tau (Bn254)

use crate::{
    groth16::{
        kzg::{Accumulator, Proof, Size, G1, G2},
        ppot::kzg::PpotCeremony,
    },
    util::{from_error, Deserializer, Serializer},
};
use alloc::vec::Vec;
use ark_std::io;
use core::fmt;
use manta_crypto::arkworks::{
    bn254::{G1Affine, G2Affine, Parameters},
    ec::{
        bn::BnParameters, short_weierstrass_jacobian::GroupAffine, ModelParameters,
        SWModelParameters,
    },
    ff::{PrimeField, ToBytes, Zero},
    pairing::Pairing,
    serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write},
};
use manta_util::cfg_iter;

#[cfg(feature = "rayon")]
use manta_util::rayon::prelude::ParallelIterator;

/// (De)Serialization used in the original PPoT ceremony
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PpotSerializer;

type BaseFieldG1Type = <<Parameters as BnParameters>::G1Parameters as ModelParameters>::BaseField;
type BaseFieldG2Type = <<Parameters as BnParameters>::G2Parameters as ModelParameters>::BaseField;

impl Deserializer<G1Affine, G1> for PpotSerializer {
    type Error = PointDeserializeError;

    fn deserialize_unchecked<R>(reader: &mut R) -> Result<G1Affine, Self::Error>
    where
        R: Read,
    {
        let mut copy = [0u8; 64];
        let _ = reader.read(&mut copy);

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

    fn check(g: &G1Affine) -> Result<(), Self::Error> {
        if !g.is_on_curve() {
            return Err(PointDeserializeError::NotOnCurve);
        } else if !g.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PointDeserializeError::NotInSubgroup);
        }
        Ok(())
    }

    /// Note that in this case the method is unchecked! This is because it is more
    /// efficient to do the in-subgroup check in parallel later.
    fn deserialize_compressed<R>(reader: &mut R) -> Result<G1Affine, Self::Error>
    where
        R: Read,
    {
        let mut copy = [0u8; 32];
        let _ = reader.read(&mut copy);

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G1Affine::zero())
            } else {
                Err(PointDeserializeError::PointAtInfinity)
            }
        } else {
            // Determine if the intended y coordinate must be greater
            // lexicographically.
            let greatest = copy[0] & (1 << 7) != 0;

            // Unset the two most significant bits.
            copy[0] &= 0x3f;

            // Now we can deserialize the remaining bytes to get x-coordinate
            let x = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..]);
            // Using `get_point_from_x` performs the on-curve check for us
            let point = G1Affine::get_point_from_x(x, greatest).ok_or(Self::Error::NotOnCurve)?;
            Ok(point)
        }
    }
}

impl Deserializer<G2Affine, G2> for PpotSerializer {
    type Error = PointDeserializeError;

    fn deserialize_unchecked<R>(reader: &mut R) -> Result<G2Affine, Self::Error>
    where
        R: Read,
    {
        let mut copy = [0u8; 128];
        let _ = reader.read(&mut copy);

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

    fn check(g: &G2Affine) -> Result<(), Self::Error> {
        if !g.is_on_curve() {
            return Err(PointDeserializeError::NotOnCurve);
        } else if !g.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PointDeserializeError::NotInSubgroup);
        }
        Ok(())
    }

    /// Note that in this case the method is unchecked! This is because it is more
    /// efficient to do the in-subgroup check in parallel later.
    fn deserialize_compressed<R>(reader: &mut R) -> Result<G2Affine, Self::Error>
    where
        R: Read,
    {
        let mut copy = [0u8; 64];
        let _ = reader.read(&mut copy);

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G2Affine::zero())
            } else {
                Err(PointDeserializeError::PointAtInfinity)
            }
        } else {
            // Determine if the intended y coordinate must be greater
            // lexicographically.
            let greatest = copy[0] & (1 << 7) != 0;

            // Unset the two most significant bits.
            copy[0] &= 0x3f;

            // Now we can deserialize the remaining bytes to get x-coordinate
            let x_c1 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..32]);
            let x_c0 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[32..]);

            let x = BaseFieldG2Type::new(x_c0, x_c1);
            // Using `get_point_from_x` performs the on-curve check for us
            let point = G2Affine::get_point_from_x(x, greatest).ok_or(Self::Error::NotOnCurve)?;
            Ok(point)
        }
    }
}

impl Serializer<G1Affine, G1> for PpotSerializer {
    fn serialize_unchecked<W>(point: &G1Affine, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        let mut res = [0u8; 32];

        if point.is_zero() {
            // Encode point at infinity
            // Final result will be reversed, so this is like modifying first byte
            res[31] |= 1 << 6;
        } else {
            let mut temp_writer = &mut res[..];

            // Write x coordinate
            point.x.write(&mut temp_writer)?;

            // Check whether y-coordinate is lexicographically greatest
            // Final result will be reversed, so this is like modifying first byte
            let negy = -point.y;
            if point.y > negy {
                res[31] |= 1 << 7;
            }
        }

        res.reverse();

        writer.write_all(&res)?;

        Ok(())
    }

    fn serialize_uncompressed<W>(point: &G1Affine, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        let mut res = [0u8; 64];

        if point.is_zero() {
            res[63] |= 1 << 6;
        } else {
            let mut temp_writer = &mut res[..];
            point.y.write(&mut temp_writer)?;
            point.x.write(&mut temp_writer)?;
        }

        res.reverse();
        writer.write_all(&res)?;
        Ok(())
    }

    fn uncompressed_size(_item: &G1Affine) -> usize {
        64
    }

    fn serialize_compressed<W>(item: &G1Affine, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        Self::serialize_unchecked(item, writer)
    }

    fn compressed_size(_item: &G1Affine) -> usize {
        32
    }
}

impl Serializer<G2Affine, G2> for PpotSerializer {
    fn serialize_unchecked<W>(point: &G2Affine, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        let mut res = [0u8; 64];

        if point.is_zero() {
            // Encode point at infinity
            // Final result will be reversed, so this is like modifying first byte
            res[63] |= 1 << 6;
        } else {
            let mut temp_writer = &mut res[..];

            // Write x coordinate
            point.x.c0.write(&mut temp_writer)?;
            point.x.c1.write(&mut temp_writer)?;

            // Check whether y-coordinate is lexicographically greatest
            // Final result will be reversed, so this is like modifying first byte
            let negy = -point.y;
            if point.y > negy {
                res[63] |= 1 << 7;
            }
        }

        res.reverse();

        writer.write_all(&res)?;

        Ok(())
    }

    fn serialize_uncompressed<W>(point: &G2Affine, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        let mut res = [0u8; 128];

        if point.is_zero() {
            res[127] |= 1 << 6;
        } else {
            let mut temp_writer = &mut res[..];
            point.y.c0.write(&mut temp_writer)?;
            point.y.c1.write(&mut temp_writer)?;
            point.x.c0.write(&mut temp_writer)?;
            point.x.c1.write(&mut temp_writer)?;
        }

        res.reverse();
        writer.write_all(&res)?;
        Ok(())
    }

    fn uncompressed_size(_item: &G2Affine) -> usize {
        128
    }

    fn serialize_compressed<W>(item: &G2Affine, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        Self::serialize_unchecked(item, writer)
    }

    fn compressed_size(_item: &G2Affine) -> usize {
        64
    }
}

/// Errors for deserialization from the encoding used in PPoT ceremony.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum PointDeserializeError {
    /// Expected a compressed representation but compression flag was `0`
    ExpectedCompressed,
    /// Expected an uncompressed representation but compression flag was `1`
    ExpectedUncompressed,
    /// Point at infinity flag is `1` but there are unexpected bits
    PointAtInfinity,
    /// A Y-coordinate was specified in a compressed representation
    ExtraYCoordinate,
    /// The decoded coordinates do not satisfy the curve equation
    NotOnCurve,
    /// The decoded curve point is not in the subgroup
    NotInSubgroup,
    /// Another curve was expected
    WrongCurve,
}

impl alloc::fmt::Display for PointDeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

impl ark_std::error::Error for PointDeserializeError {}

impl From<PointDeserializeError> for SerializationError {
    fn from(e: PointDeserializeError) -> Self {
        io::Error::new(io::ErrorKind::Other, e).into()
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

/// Compression of PPoT transcript curve points
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Compressed {
    /// Uncompressed representation
    No,
    /// Compressed representation
    Yes,
}

/// Calculates position in the mmap of specific parts of accumulator.
/// This is currently specialized to PPoT Bn254 challenge/response files.
/// In particular, it assumes the file has a 64-byte hash as its header.
#[inline]
fn calculate_mmap_position(
    index: usize,
    element_type: ElementType,
    compression: Compressed,
) -> usize {
    // These correspond to the serialization of Bn254 curve points used in PPoT
    const G1_UNCOMPRESSED_BYTE_SIZE: usize = 64;
    const G2_UNCOMPRESSED_BYTE_SIZE: usize = 128;
    const G1_COMPRESSED_BYTE_SIZE: usize = 32;
    const G2_COMPRESSED_BYTE_SIZE: usize = 64;
    const REQUIRED_POWER: usize = 28;
    const TAU_POWERS_LENGTH: usize = 1 << REQUIRED_POWER;
    const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;
    const HASH_SIZE: usize = 64;

    let (g1_size, g2_size) = match compression {
        Compressed::No => (G1_UNCOMPRESSED_BYTE_SIZE, G2_UNCOMPRESSED_BYTE_SIZE),
        Compressed::Yes => (G1_COMPRESSED_BYTE_SIZE, G2_COMPRESSED_BYTE_SIZE),
    };

    let required_tau_g1_power = TAU_POWERS_G1_LENGTH;
    let required_power = TAU_POWERS_LENGTH;

    let position = match element_type {
        ElementType::TauG1 => {
            let mut position = 0;
            position += g1_size * index;
            assert!(index < TAU_POWERS_G1_LENGTH);

            position
        }
        ElementType::TauG2 => {
            let mut position = 0;
            position += g1_size * required_tau_g1_power;
            assert!(index < TAU_POWERS_LENGTH);
            position += g2_size * index;

            position
        }
        ElementType::AlphaG1 => {
            let mut position = 0;
            position += g1_size * required_tau_g1_power;
            position += g2_size * required_power;
            assert!(index < TAU_POWERS_LENGTH);
            position += g1_size * index;

            position
        }
        ElementType::BetaG1 => {
            let mut position = 0;
            position += g1_size * required_tau_g1_power;
            position += g2_size * required_power;
            position += g1_size * required_power;
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

/// The types of curve points in a Groth16 KZG accumulator
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ElementType {
    /// Tau G1
    TauG1,
    /// Tau G2
    TauG2,
    /// Alpha G1
    AlphaG1,
    /// Beta G1
    BetaG1,
    /// Beta G2
    BetaG2,
}

impl ElementType {
    /// Returns the size of a given type of point with the specified compression.
    /// This function is specific to the PPoT Bn254 serialization.
    fn get_size(&self, compression: Compressed) -> usize {
        match compression {
            Compressed::No => {
                if self.is_g1_type() {
                    64
                } else {
                    128
                }
            }
            Compressed::Yes => {
                if self.is_g1_type() {
                    32
                } else {
                    64
                }
            }
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
    reader: &[u8],
    element: ElementType,
    compression: Compressed,
) -> Result<Vec<G1Affine>, PointDeserializeError>
where
    S: Size,
{
    let size = element.num_powers::<S>();
    let mut powers = Vec::new();
    let mut start_position = calculate_mmap_position(0, element, compression);
    let mut end_position = start_position + element.get_size(compression);
    for _ in 0..size {
        let mut reader = &reader[start_position..end_position];

        if element.is_g1_type() {
            let point = match compression {
                Compressed::No => {
                    <PpotCeremony as Deserializer<G1Affine, G1>>::deserialize_unchecked(
                        &mut reader,
                    )?
                }
                Compressed::Yes => {
                    <PpotCeremony as Deserializer<G1Affine, G1>>::deserialize_compressed(
                        &mut reader,
                    )?
                }
            };
            // point will be checked below
            powers.push(point);
        } else {
            return Err(PointDeserializeError::WrongCurve);
        }
        start_position = end_position;
        end_position += element.get_size(compression);
    }

    // Do curve point checks in parallel
    match compression {
        Compressed::No => cfg_iter!(powers).for_each(|g| curve_point_checks(g).unwrap()),
        Compressed::Yes => cfg_iter!(powers).try_for_each(|g| {
            if !g.is_in_correct_subgroup_assuming_on_curve() {
                Err(PointDeserializeError::NotInSubgroup)
            } else {
                Ok(())
            }
        })?,
    }
    Ok(powers)
}

/// Reads `size` many elements of `element_type` from PPoT challenge file.
#[inline]
pub fn read_g2_powers<S>(
    reader: &[u8],
    element: ElementType,
    compression: Compressed,
) -> Result<Vec<G2Affine>, PointDeserializeError>
where
    S: Size,
{
    let size = element.num_powers::<S>();
    let mut powers = Vec::new();
    let mut start_position = calculate_mmap_position(0, element, compression);
    let mut end_position = start_position + element.get_size(compression);
    for _ in 0..size {
        let mut reader = &reader[start_position..end_position];

        if !element.is_g1_type() {
            let point = match compression {
                Compressed::No => {
                    <PpotCeremony as Deserializer<G2Affine, G2>>::deserialize_unchecked(
                        &mut reader,
                    )?
                }
                Compressed::Yes => {
                    <PpotCeremony as Deserializer<G2Affine, G2>>::deserialize_compressed(
                        &mut reader,
                    )?
                }
            };
            // point will be checked below
            powers.push(point);
        } else {
            return Err(PointDeserializeError::WrongCurve);
        }
        start_position = end_position;
        end_position += element.get_size(compression);
    }
    // Do curve point checks in parallel
    match compression {
        Compressed::No => cfg_iter!(powers).for_each(|g| curve_point_checks(g).unwrap()),
        Compressed::Yes => cfg_iter!(powers).try_for_each(|g| {
            if !g.is_in_correct_subgroup_assuming_on_curve() {
                Err(PointDeserializeError::NotInSubgroup)
            } else {
                Ok(())
            }
        })?,
    }

    Ok(powers)
}

/// Reads the proof of correct KZG contribution
/// This is specific to the compressed PPoT transcript called `response`,
/// since only it contains this proof.
#[inline]
pub fn read_kzg_proof(reader: &[u8]) -> Result<Proof<PpotCeremony>, SerializationError> {
    let position = 64
        + (PpotCeremony::G1_POWERS + 2 * PpotCeremony::G2_POWERS) * 32
        + (PpotCeremony::G2_POWERS + 1) * 64;

    Proof::deserialize_uncompressed(&reader[position..position + 6 * 64 + 3 * 128])
}

/// Extracts a subaccumulator of size specified by `C`. Specific to PPoT challenge file.
#[inline]
pub fn read_subaccumulator<C>(
    reader: &[u8],
    compression: Compressed,
) -> Result<Accumulator<C>, PointDeserializeError>
where
    C: Pairing<G1 = G1Affine, G2 = G2Affine> + Size,
{
    Ok(Accumulator {
        tau_powers_g1: read_g1_powers::<C>(reader, ElementType::TauG1, compression)?,
        tau_powers_g2: read_g2_powers::<C>(reader, ElementType::TauG2, compression)?,
        alpha_tau_powers_g1: read_g1_powers::<C>(reader, ElementType::AlphaG1, compression)?,
        beta_tau_powers_g1: read_g1_powers::<C>(reader, ElementType::BetaG1, compression)?,
        beta_g2: read_g2_powers::<C>(reader, ElementType::BetaG2, compression)?[0],
    })
}

/// Arkworks Canonical(De)Serialize
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArkworksSerialization;

impl<P> Serializer<GroupAffine<P>> for ArkworksSerialization
where
    P: SWModelParameters,
{
    #[inline]
    fn serialize_unchecked<W>(item: &GroupAffine<P>, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize_unchecked(item, writer).map_err(from_error)
    }

    #[inline]
    fn serialize_uncompressed<W>(item: &GroupAffine<P>, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize_uncompressed(item, writer).map_err(from_error)
    }

    #[inline]
    fn uncompressed_size(item: &GroupAffine<P>) -> usize {
        CanonicalSerialize::uncompressed_size(item)
    }

    #[inline]
    fn serialize_compressed<W>(item: &GroupAffine<P>, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        CanonicalSerialize::serialize(item, writer).map_err(from_error)
    }

    #[inline]
    fn compressed_size(item: &GroupAffine<P>) -> usize {
        CanonicalSerialize::serialized_size(item)
    }
}

impl<P> Deserializer<GroupAffine<P>> for ArkworksSerialization
where
    P: SWModelParameters,
{
    type Error = SerializationError;

    #[inline]
    fn deserialize_unchecked<R>(reader: &mut R) -> Result<GroupAffine<P>, Self::Error>
    where
        R: Read,
    {
        CanonicalDeserialize::deserialize_unchecked(reader)
    }

    #[inline]
    fn deserialize_compressed<R>(reader: &mut R) -> Result<GroupAffine<P>, Self::Error>
    where
        R: Read,
    {
        CanonicalDeserialize::deserialize_uncompressed(reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that serializing then deserializing randomly sampled curve points
    /// is identity.
    #[test]
    fn deserialization_test() {
        use manta_crypto::{
            arkworks::ec::{AffineCurve, ProjectiveCurve},
            rand::{ChaCha20Rng, Sample, SeedableRng},
        };

        // Generate random points from each curve
        const N: usize = 100; // number of samples
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let g1: Vec<G1Affine> = (0..N)
            .into_iter()
            .map(|_| <G1Affine as AffineCurve>::Projective::gen(&mut rng).into_affine())
            .collect();
        let g2: Vec<G2Affine> = (0..N)
            .into_iter()
            .map(|_| <G2Affine as AffineCurve>::Projective::gen(&mut rng).into_affine())
            .collect();

        // First Compressed serialization
        let mut file = Vec::<u8>::new();
        g1.iter().for_each(|g| {
            <PpotCeremony as Serializer<G1Affine, G1>>::serialize_unchecked(g, &mut file).unwrap()
        });
        assert_eq!(
            file.len(),
            N * <PpotCeremony as Serializer::<G1Affine, G1>>::compressed_size(&g1[0])
        );

        let mut g1_deser = Vec::<G1Affine>::new();

        println!("Deserializing now ");

        for i in 0..N {
            let start = i * <PpotCeremony as Serializer<G1Affine, G1>>::compressed_size(&g1[0]);
            let end = (i + 1) * <PpotCeremony as Serializer<G1Affine, G1>>::compressed_size(&g1[0]);
            let mut temp = &file[start..end];
            match <PpotCeremony as Deserializer<G1Affine, G1>>::deserialize_compressed(&mut temp) {
                Ok(point) => g1_deser.push(point),
                Err(e) => {
                    println!("Error {:?} occurred on point {:?}", e, i);
                }
            }
        }
        assert_eq!(g1, g1_deser);

        // Now uncompressed serialization
        let mut file = Vec::<u8>::new();
        g1.iter().for_each(|g| {
            <PpotCeremony as Serializer<G1Affine, G1>>::serialize_uncompressed(g, &mut file)
                .unwrap()
        });
        assert_eq!(
            file.len(),
            N * <PpotCeremony as Serializer::<G1Affine, G1>>::uncompressed_size(&g1[0])
        );

        let mut g1_deser = Vec::<G1Affine>::new();

        println!("Deserializing now ");

        for i in 0..N {
            let start = i * <PpotCeremony as Serializer<G1Affine, G1>>::uncompressed_size(&g1[0]);
            let end =
                (i + 1) * <PpotCeremony as Serializer<G1Affine, G1>>::uncompressed_size(&g1[0]);
            let mut temp = &file[start..end];
            match <PpotCeremony as Deserializer<G1Affine, G1>>::deserialize_uncompressed(&mut temp)
            {
                Ok(point) => g1_deser.push(point),
                Err(e) => {
                    println!("Error {:?} occurred on point {:?}", e, i);
                }
            }
        }
        assert_eq!(g1, g1_deser);

        // REPEAT

        // First Compressed serialization
        let mut file = Vec::<u8>::new();
        g2.iter().for_each(|g| {
            <PpotCeremony as Serializer<G2Affine, G2>>::serialize_unchecked(g, &mut file).unwrap()
        });
        assert_eq!(
            file.len(),
            N * <PpotCeremony as Serializer::<G2Affine, G2>>::compressed_size(&g2[0])
        );

        let mut g2_deser = Vec::<G2Affine>::new();

        println!("Deserializing now ");

        for i in 0..N {
            let start = i * <PpotCeremony as Serializer<G2Affine, G2>>::compressed_size(&g2[0]);
            let end = (i + 1) * <PpotCeremony as Serializer<G2Affine, G2>>::compressed_size(&g2[0]);
            let mut temp = &file[start..end];
            match <PpotCeremony as Deserializer<G2Affine, G2>>::deserialize_compressed(&mut temp) {
                Ok(point) => g2_deser.push(point),
                Err(e) => {
                    println!("Error {:?} occurred on point {:?}", e, i);
                }
            }
        }
        assert_eq!(g2, g2_deser);

        // Now uncompressed serialization
        let mut file = Vec::<u8>::new();
        g2.iter().for_each(|g| {
            <PpotCeremony as Serializer<G2Affine, G2>>::serialize_uncompressed(g, &mut file)
                .unwrap()
        });
        assert_eq!(
            file.len(),
            N * <PpotCeremony as Serializer::<G2Affine, G2>>::uncompressed_size(&g2[0])
        );

        let mut g2_deser = Vec::<G2Affine>::new();

        println!("Deserializing now ");

        for i in 0..N {
            let start = i * <PpotCeremony as Serializer<G2Affine, G2>>::uncompressed_size(&g2[0]);
            let end =
                (i + 1) * <PpotCeremony as Serializer<G2Affine, G2>>::uncompressed_size(&g2[0]);
            let mut temp = &file[start..end];
            match <PpotCeremony as Deserializer<G2Affine, G2>>::deserialize_uncompressed(&mut temp)
            {
                Ok(point) => g2_deser.push(point),
                Err(e) => {
                    println!("Error {:?} occurred on point {:?}", e, i);
                }
            }
        }
        assert_eq!(g2, g2_deser);
    }

    /// Compares the accumulators stored in response_0071 and challenge_0072
    #[ignore] // NOTE: Adds `ignore` such that CI does NOT run this test while still allowing developers to test.
    #[test]
    pub fn compare_response_challenge_accumulators_test() {
        use crate::groth16::ppot::kzg::PerpetualPowersOfTauCeremony;
        use memmap::MmapOptions;
        use std::{fs::OpenOptions, time::Instant};

        const POWERS: usize = 1 << 5;
        /// Configuration for a Phase1 Ceremony large enough to support MantaPay circuits
        pub type SubCeremony = PerpetualPowersOfTauCeremony<PpotSerializer, POWERS>;

        // Try to load `./challenge` from disk.
        println!("Reading accumulator from challenge file");
        let now = Instant::now();
        let reader = OpenOptions::new()
            .read(true)
            .open("/Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072")
            .expect("unable open `./challenge` in this directory");
        // Make a memory map
        let challenge_map = unsafe {
            MmapOptions::new()
                .map(&reader)
                .expect("unable to create a memory map for input")
        };
        let challenge_acc =
            read_subaccumulator::<SubCeremony>(&challenge_map, Compressed::No).unwrap();
        println!("Read uncompressed accumulator in {:?}", now.elapsed());

        // Try to load `./response` from disk.
        println!("Reading accumulator from response file");
        let now = Instant::now();
        let reader = OpenOptions::new()
            .read(true)
            .open("/Users/thomascnorton/Documents/Manta/trusted-setup/response_0071")
            .expect("unable open `./response` in this directory");
        // Make a memory map
        let response_map = unsafe {
            MmapOptions::new()
                .map(&reader)
                .expect("unable to create a memory map for input")
        };
        let response_acc =
            read_subaccumulator::<SubCeremony>(&response_map, Compressed::Yes).unwrap();
        println!("Read compressed accumulator in {:?}", now.elapsed());

        assert_eq!(challenge_acc, response_acc)
    }
}
