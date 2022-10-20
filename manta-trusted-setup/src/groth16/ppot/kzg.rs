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

//! KZG (Phase 1) with Bn254 Backend for MantaPay Groth16 Trusted Setup

use crate::{
    groth16::{
        kzg::{Accumulator, Configuration, Proof, Size, G1, G2},
        ppot::{hashing::PpotHasher, serialization::PpotSerializer},
    },
    util::{BlakeHasher, Deserializer, Serializer},
};
use ark_std::io;
use blake2::Digest;
use core::marker::PhantomData;
use manta_crypto::arkworks::{
    bn254::{Bn254, Fr, G1Affine, G2Affine},
    ec::{AffineCurve, PairingEngine},
    pairing::Pairing,
    serialize::{CanonicalSerialize, Read, Write},
};
use manta_util::into_array_unchecked;

/// Configuration of the Perpetual Powers of Tau Ceremony
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PerpetualPowersOfTauCeremony<S, const POWERS: usize>(PhantomData<S>);

impl<S, const POWERS: usize> Size for PerpetualPowersOfTauCeremony<S, POWERS> {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = POWERS;
}

impl<S, const POWERS: usize> Pairing for PerpetualPowersOfTauCeremony<S, POWERS> {
    type Scalar = Fr;
    type G1 = G1Affine;
    type G1Prepared = <Bn254 as PairingEngine>::G1Prepared;
    type G2 = G2Affine;
    type G2Prepared = <Bn254 as PairingEngine>::G2Prepared;
    type Pairing = Bn254;

    #[inline]
    fn g1_prime_subgroup_generator() -> Self::G1 {
        G1Affine::prime_subgroup_generator()
    }

    #[inline]
    fn g2_prime_subgroup_generator() -> Self::G2 {
        G2Affine::prime_subgroup_generator()
    }
}

impl<S, const POWERS: usize> Configuration for PerpetualPowersOfTauCeremony<S, POWERS>
where
    S: Serializer<G1Affine, G1>, // TODO: goes away with below todo
{
    type DomainTag = u8;
    type Challenge = [u8; 64];
    type Response = [u8; 64];
    type HashToGroup = PpotHasher; // TODO : Fix KZGHasher and use here

    const TAU_DOMAIN_TAG: Self::DomainTag = 0;
    const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
    const BETA_DOMAIN_TAG: Self::DomainTag = 2;

    #[inline]
    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
        Self::HashToGroup { domain_tag }
    }

    #[inline]
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
        hasher.0.update(challenge);
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

impl<T, M, S, const POWERS: usize> Deserializer<T, M> for PerpetualPowersOfTauCeremony<S, POWERS>
where
    S: Deserializer<T, M>,
{
    type Error = S::Error;

    #[inline]
    fn check(item: &T) -> Result<(), Self::Error> {
        S::check(item)
    }

    #[inline]
    fn deserialize_unchecked<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        S::deserialize_unchecked(reader)
    }

    #[inline]
    fn deserialize_uncompressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        S::deserialize_uncompressed(reader)
    }

    #[inline]
    fn deserialize_compressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        S::deserialize_compressed(reader)
    }
}

impl<M, T, S, const POWERS: usize> Serializer<T, M> for PerpetualPowersOfTauCeremony<S, POWERS>
where
    S: Serializer<T, M>,
{
    #[inline]
    fn serialize_unchecked<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        S::serialize_unchecked(item, writer)
    }

    #[inline]
    fn serialize_uncompressed<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        S::serialize_uncompressed(item, writer)
    }

    #[inline]
    fn uncompressed_size(item: &T) -> usize {
        S::uncompressed_size(item)
    }

    #[inline]
    fn serialize_compressed<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        S::serialize_compressed(item, writer)
    }

    #[inline]
    fn compressed_size(item: &T) -> usize {
        S::compressed_size(item)
    }
}

/// Number of powers used in the original PPoT
const PPOT_POWERS: usize = 1 << 28;
/// Type of the original ceremony
pub type PpotCeremony = PerpetualPowersOfTauCeremony<PpotSerializer, PPOT_POWERS>;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
/// Tools for decompressing the `response` files of PPoT
pub mod decompression {
    use super::*;
    use crate::{
        groth16::ppot::serialization::{
            read_all_g2_powers, read_g1_powers, read_g2_powers, Compressed, ElementType,
            PointDeserializeError,
        },
        util::Serializer,
    };
    use manta_crypto::arkworks::serialize::CanonicalDeserialize;
    use memmap::MmapOptions;
    use std::{cmp::min, fs::OpenOptions, path::PathBuf};

    /// Decompresses a `response` file to a `challenge` file, assuming its hash
    /// has been pre-computed and passed as argument. This creates challenge file
    /// at the specified `path` with Arkworks [`CanonicalSerialize`] encoding.
    /// Uses approx. 1 GB chunks in case files are large.
    pub fn decompress_reencode_response<S>(
        reader: &[u8],
        hash: [u8; 64],
        path: PathBuf,
    ) -> Result<(), PointDeserializeError>
    where
        S: Size,
    {
        // TODO: Choose this number to have chunks of desired size
        let chunk_size: usize = 1 << 12;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .expect("Failed to open target file at given path");
        let mut powers_read = 0;

        // First write the 64-byte hash to file
        file.write_all(&hash).expect("Failed to write hash to file");

        // Read TauG1 powers
        while powers_read < ElementType::TauG1.num_powers::<S>() {
            let powers = read_g1_powers(
                reader,
                ElementType::TauG1,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::TauG1.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                element
                    .serialize_uncompressed(&mut file)
                    .expect("Encountered serialization error");
            }
            println!("Have serialized {} tau_g1 powers", powers_read);
            powers_read += chunk_size;
        }
        powers_read = 0;

        // Read TauG2 powers
        while powers_read < ElementType::TauG2.num_powers::<S>() {
            let powers = read_g2_powers(
                reader,
                ElementType::TauG2,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::TauG2.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                element
                    .serialize_uncompressed(&mut file)
                    .expect("Encountered serialization error");
            }
            println!("Have serialized {} tau_g2 powers", powers_read);
            powers_read += chunk_size;
        }
        powers_read = 0;

        // Read AlphaTauG1 powers
        while powers_read < ElementType::AlphaG1.num_powers::<S>() {
            let powers = read_g1_powers(
                reader,
                ElementType::AlphaG1,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::AlphaG1.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                element
                    .serialize_uncompressed(&mut file)
                    .expect("Encountered serialization error");
            }
            println!("Have serialized {} alpha_tau_g1 powers", powers_read);
            powers_read += chunk_size;
        }
        powers_read = 0;

        // Read BetaTauG1 powers
        while powers_read < ElementType::BetaG1.num_powers::<S>() {
            let powers = read_g1_powers(
                reader,
                ElementType::BetaG1,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::BetaG1.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                element
                    .serialize_uncompressed(&mut file)
                    .expect("Encountered serialization error");
            }
            println!("Have serialized {} beta_tau_g1 powers", powers_read);
            powers_read += chunk_size;
        }

        // Read BetaG2
        let element =
            read_all_g2_powers::<PpotCeremony>(reader, ElementType::BetaG2, Compressed::Yes)?[0];
        element
            .serialize_uncompressed(&mut file)
            .expect("Unable to serialize betaG2");

        Ok(())
    }

    /// Decompresses a `response` file to a `challenge` file, assuming its hash
    /// has been pre-computed and passed as argument. This creates challenge file
    /// at the specified `path` with same bellman encoding used by PPoT.
    /// Uses approx. 1 GB chunks in case files are large.
    pub fn decompress_response<S>(
        reader: &[u8],
        hash: [u8; 64],
        path: PathBuf,
    ) -> Result<(), PointDeserializeError>
    where
        S: Size,
    {
        // Choose this number to have chunks of desired size
        let chunk_size: usize = 1 << 18;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .expect("Failed to open target file at given path");
        let mut powers_read = 0;

        // First write the 64-byte hash to file
        file.write_all(&hash).expect("Failed to write hash to file");

        // Read TauG1 powers
        while powers_read < ElementType::TauG1.num_powers::<S>() {
            let powers = read_g1_powers(
                reader,
                ElementType::TauG1,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::TauG1.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                <PpotCeremony as Serializer<G1Affine, G1>>::serialize_uncompressed(
                    element, &mut file,
                )
                .expect("Unable to serialize");
            }
            println!("Have serialized {} tau_g1 powers", powers_read);
            powers_read += chunk_size;
        }
        powers_read = 0;

        // Read TauG2 powers
        while powers_read < ElementType::TauG2.num_powers::<S>() {
            let powers = read_g2_powers(
                reader,
                ElementType::TauG2,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::TauG2.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                <PpotCeremony as Serializer<G2Affine, G2>>::serialize_uncompressed(
                    element, &mut file,
                )
                .expect("Unable to serialize");
            }
            println!("Have serialized {} tau_g2 powers", powers_read);
            powers_read += chunk_size;
        }
        powers_read = 0;

        // Read AlphaTauG1 powers
        while powers_read < ElementType::AlphaG1.num_powers::<S>() {
            let powers = read_g1_powers(
                reader,
                ElementType::AlphaG1,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::AlphaG1.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                <PpotCeremony as Serializer<G1Affine, G1>>::serialize_uncompressed(
                    element, &mut file,
                )
                .expect("Unable to serialize");
            }
            println!("Have serialized {} alpha_tau_g1 powers", powers_read);
            powers_read += chunk_size;
        }
        powers_read = 0;

        // Read BetaTauG1 powers
        while powers_read < ElementType::BetaG1.num_powers::<S>() {
            let powers = read_g1_powers(
                reader,
                ElementType::BetaG1,
                Compressed::Yes,
                min(
                    chunk_size,
                    ElementType::BetaG1.num_powers::<S>() - powers_read,
                ),
                powers_read,
            )?;
            for element in powers.iter() {
                <PpotCeremony as Serializer<G1Affine, G1>>::serialize_uncompressed(
                    element, &mut file,
                )
                .expect("Unable to serialize");
            }
            println!("Have serialized {} beta_tau_g1 powers", powers_read);
            powers_read += chunk_size;
        }

        // Read BetaG2
        let element =
            read_all_g2_powers::<PpotCeremony>(reader, ElementType::BetaG2, Compressed::Yes)?[0];
        <PpotCeremony as Serializer<G2Affine, G2>>::serialize_uncompressed(&element, &mut file)
            .expect("Unable to serialize");

        Ok(())
    }

    #[ignore] // NOTE: Adds `ignore` such that CI does NOT run this test while still allowing developers to test.
    #[test]
    pub fn decompress_test() {
        // cargo test decompress_test
        let source_path =
            PathBuf::from("/Users/thomascnorton/Documents/Manta/trusted-setup/response_0070");
        let target_path = source_path
            .parent()
            .expect("source path has no parent")
            .join("response_70_decompressed");
        let file = OpenOptions::new()
            .read(true)
            .open(source_path)
            .expect("Cannot open response file at path");

        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .expect("Unable to create memory map for input")
        };
        let hash = [1u8; 64];
        // decompress_reencode_response::<PpotCeremony>(&mmap, hash, target_path).expect("Error decompressing");
        // I already did that above step with the bin, but I only let it get to about halfway through. Let's check
        // that that part was decompressed accurately:

        let mut target_file = OpenOptions::new()
            .read(true)
            .open(target_path)
            .expect("Cannot open target file");
        let mut written_hash = [0u8; 64];
        assert_eq!(target_file.read(&mut written_hash[..]).unwrap(), 64);
        assert_eq!(written_hash, hash);

        let g1_powers = read_g1_powers(&mmap, ElementType::TauG1, Compressed::Yes, 100, 0)
            .expect("Cannot read from response file");
        // let g2_powers = read_g2_powers(&mmap, ElementType::TauG2, Compressed::Yes, 100, 0).expect("Cannot read from response file");
        for element in g1_powers.iter() {
            let point: G1Affine = CanonicalDeserialize::deserialize_uncompressed(&mut target_file)
                .expect("Deserialization error");
            assert_eq!(point, *element);
        }
    }
}
