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

//! Serialization Utilities

use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::{
    bls12::Bls12Parameters, ModelParameters,
};
use ark_ff::{PrimeField, ToBytes};
pub use ark_ff::{One, Zero};
pub use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};
use ark_std::io;
pub use manta_crypto::rand::Sample;

use blake2::{digest::consts::U8, Blake2b};


/// TODO
pub enum PointDeserializeError {
    /// TODO
    CompressionFlag,
    /// TODO
    ExpectedCompressed,
    /// TODO
    ExpectedUncompressed,
    /// TODO
    PointAtInfinity,
    /// TODO
    ExtraYCoordinate,
    /// TODO
    NotOnCurve,
    /// TODO
    NotInSubgroup,
}

type BaseFieldG1Type =
    <<ark_bls12_381::Parameters as Bls12Parameters>::G1Parameters as ModelParameters>::BaseField;
type BaseFieldG2Type =
    <<ark_bls12_381::Parameters as Bls12Parameters>::G2Parameters as ModelParameters>::BaseField;

/// TODO
pub fn serialize_g1_uncompressed<W>(point: &G1Affine, writer: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    let mut res = [0u8; 96];
    if point.is_zero() {
        res[95] |= 1 << 6;
    } else {
        let mut temp_writer = &mut res[..];
        point.y.write(&mut temp_writer)?;
        point.x.write(&mut temp_writer)?;
    }
    res.reverse();
    writer.write_all(&res)?;
    Ok(())
}

/// TODO
#[inline]
pub fn deserialize_g1_compressed<R>(reader: &mut R) -> Result<G1Affine, PointDeserializeError>
where
    R: Read,
{
    let mut copy = [0u8; 48];
    let _ = reader.read(&mut copy); // should I deal with the number of bytes read output?
                                    // Check the compression flag
    if copy[0] & (1 << 7) == 0 {
        // If that bit is zero then the reader contains an uncompressed representation
        return Err(PointDeserializeError::ExpectedCompressed);
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
        let greatest = copy[0] & (1 << 5) != 0;

        // Now unset the first three bits
        copy[0] &= 0x1f;

        // Now we can deserialize the remaining bytes to get x-coordinate
        let x = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..]);
        // Using `get_point_from_x` performs the on-curve check for us
        let point =
            G1Affine::get_point_from_x(x, greatest).ok_or(PointDeserializeError::NotOnCurve)?;

        // Check that the point is in subgroup
        if !G1Affine::is_in_correct_subgroup_assuming_on_curve(&point) {
            return Err(PointDeserializeError::NotInSubgroup);
        }
        Ok(point)
    }
}

/// Only makes sense for this to be deserialization from uncompressed bytes since
/// deserializing from compressed implies at least doing an on-curve check
#[inline]
pub fn deserialize_g1_unchecked<R>(reader: &mut R) -> Result<G1Affine, PointDeserializeError>
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

/// TODO
pub fn serialize_g2_compressed<W>(point: &G2Affine, writer: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    let mut res = [0u8; 96];

    if point.is_zero() {
        // Encode point at infinity
        // Final result will be reversed, so this is like modifying first byte
        res[95] |= 1 << 6;
    } else {
        let mut temp_writer = &mut res[..];

        // Write x coordinate
        point.x.c0.write(&mut temp_writer)?;
        point.x.c1.write(&mut temp_writer)?;

        // Check whether y-coordinate is lexicographically greatest
        // Final result will be reversed, so this is like modifying first byte
        let negy = -point.y;
        if point.y > negy {
            res[95] |= 1 << 5;
        }
    }
    // Compression flag
    res[95] |= 1 << 7;

    res.reverse();

    writer.write_all(&res)?;

    Ok(())
}

/// TODO
#[inline]
pub fn serialize_g2_uncompressed<W>(point: &G2Affine, writer: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    let mut res = [0u8; 192];

    if point.is_zero() {
        // Encode point at infinity
        // Final result will be reversed, so this is like modifying first byte
        res[191] |= 1 << 6;
    } else {
        let mut temp_writer = &mut res[..];

        // Write x and y coordinates
        // The final result must be reversed to match endianness of pairing library
        // so we write `y` and then `x`
        point.y.c0.write(&mut temp_writer)?;
        point.y.c1.write(&mut temp_writer)?;
        point.x.c0.write(&mut temp_writer)?;
        point.x.c1.write(&mut temp_writer)?;
    }

    res.reverse();

    writer.write_all(&res)?;

    Ok(())
}

/// TODO
pub fn deserialize_g2_compressed<R>(reader: &mut R) -> Result<G2Affine, PointDeserializeError>
where
    R: Read,
{
    let mut copy = [0u8; 96];
    let _ = reader.read(&mut copy); // should I deal with the number of bytes read output?

    // Check the compression flag
    if copy[0] & (1 << 7) == 0 {
        // If that bit is zero then the reader contains an uncompressed representation
        return Err(PointDeserializeError::ExpectedCompressed);
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
        // Check y-coordinate flag
        let greatest = copy[0] & (1 << 5) != 0;

        // Now unset the first three bits
        copy[0] &= 0x1f;

        // Now we can deserialize the remaining bytes to get x-coordinate
        let x_c1 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..48]);
        let x_c0 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[48..]);

        let x = BaseFieldG2Type::new(x_c0, x_c1);

        // Using `get_point_from_x` performs the on-curve check for us
        let point = match G2Affine::get_point_from_x(x, greatest) {
            Some(point) => point,
            _ => return Err(PointDeserializeError::NotOnCurve),
        };
        // Check that the point is in subgroup
        if !G2Affine::is_in_correct_subgroup_assuming_on_curve(&point) {
            return Err(PointDeserializeError::NotInSubgroup);
        }
        Ok(point)
    }
}

/// TODO
#[inline]
pub fn deserialize_g2_unchecked<R>(reader: &mut R) -> Result<G2Affine, PointDeserializeError>
where
    R: Read,
{
    let mut copy = [0u8; 192];
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
        // Check y-coordinate flag
        if copy[0] & (1 << 5) != 0 {
            // Since this representation is uncompressed the flag should be set to 0
            return Err(PointDeserializeError::ExtraYCoordinate);
        }

        // Now unset the first three bits
        copy[0] &= 0x1f;

        // Now we can deserialize the remaining bytes to field elements
        let x_c1 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[..48]);
        let x_c0 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[48..96]);
        let y_c1 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[96..144]);
        let y_c0 = BaseFieldG1Type::from_be_bytes_mod_order(&copy[144..]);
        // Recall BaseFieldG2 is a quadratic ext'n of BaseFieldG1
        let x = BaseFieldG2Type::new(x_c0, x_c1);
        let y = BaseFieldG2Type::new(y_c0, y_c1);

        Ok(G2Affine::new(x, y, false))
    }
}
