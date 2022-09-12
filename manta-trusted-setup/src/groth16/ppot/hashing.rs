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

//! Utilities to match hashing to G2 curve used in Perpetual Powers of Tau Ceremony

use crate::{
    groth16::{kzg::G1, ppot::kzg::PerpetualPowersOfTauCeremony},
    util::{hash_to_group, BlakeHasher, Serializer},
};
use blake2::Digest;
use manta_crypto::{
    arkworks::{
        bn254::{self, Fq, Fq2, G1Affine, G2Affine},
        ec::{short_weierstrass_jacobian::GroupAffine, ProjectiveCurve, SWModelParameters},
        ff::{BigInteger256, Fp256, FpParameters, Zero},
        ratio::HashToGroup,
    },
    rand::{RngCore, Sample},
};
use manta_util::into_array_unchecked;

/// The G2 hasher used in the PPoT ceremony
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PpotHasher {
    /// Domain separation for tau, alpha, beta
    pub domain_tag: u8,
}

impl<S, const POWERS: usize, const N: usize>
    HashToGroup<PerpetualPowersOfTauCeremony<S, POWERS>, [u8; N]> for PpotHasher
where
    S: Serializer<G1Affine, G1>,
{
    #[inline]
    fn hash(&self, challenge: &[u8; N], pair: (&G1Affine, &G1Affine)) -> G2Affine {
        let mut hasher = BlakeHasher::default();
        hasher.0.update([self.domain_tag]);
        hasher.0.update(challenge);
        <PerpetualPowersOfTauCeremony<S, POWERS> as Serializer<G1Affine, G1>>::serialize_uncompressed(pair.0, &mut hasher)
            .unwrap();
        <PerpetualPowersOfTauCeremony<S, POWERS> as Serializer<G1Affine, G1>>::serialize_uncompressed(pair.1, &mut hasher)
            .unwrap();
        hash_to_group::<_, PpotDistribution, 64>(into_array_unchecked(hasher.0.finalize()))
    }
}

/// A distribution to replicate random sampling as it was done
/// during the Ppot ceremony, which used `rand v. 0.4`.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PpotDistribution;

impl<P> Sample<PpotDistribution> for GroupAffine<P>
where
    P: SWModelParameters,
    P::BaseField: Sample<PpotDistribution>,
{
    fn sample<R>(distribution: PpotDistribution, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        loop {
            let x = P::BaseField::sample(distribution, rng);
            let greatest = bool::sample(distribution, rng);
            if let Some(p) = Self::get_point_from_x(x, greatest) {
                let p = p.scale_by_cofactor();
                if !p.is_zero() {
                    return p.into_affine();
                }
            }
        }
    }
}

impl Sample<PpotDistribution> for Fq {
    fn sample<R>(distribution: PpotDistribution, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        loop {
            let mut tmp = BigInteger256::sample(distribution, rng);

            // Mask away the unused bits at the beginning.
            tmp.as_mut()[3] &= 0xffffffffffffffff >> bn254::FqParameters::REPR_SHAVE_BITS;
            if tmp < bn254::FqParameters::MODULUS {
                return Fp256::new(tmp);
            }
        }
    }
}
impl Sample<PpotDistribution> for Fq2 {
    fn sample<R>(distribution: PpotDistribution, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(Fq::sample(distribution, rng), Fq::sample(distribution, rng))
    }
}

impl Sample<PpotDistribution> for BigInteger256 {
    fn sample<R>(distribution: PpotDistribution, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        BigInteger256([
            u64::sample(distribution, rng),
            u64::sample(distribution, rng),
            u64::sample(distribution, rng),
            u64::sample(distribution, rng),
        ])
    }
}

impl Sample<PpotDistribution> for u64 {
    fn sample<R>(_: PpotDistribution, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        ((rng.next_u32() as u64) << 32) | (rng.next_u32() as u64)
    }
}

impl Sample<PpotDistribution> for bool {
    fn sample<R>(_: PpotDistribution, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        (rng.next_u32() as u8) & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::{
        kzg::{Accumulator, Proof},
        ppot::{
            kzg::PpotCeremony,
            serialization::{read_kzg_proof, read_subaccumulator, Compressed, PpotSerializer},
        },
    };

    const POWERS: usize = 1 << 5;
    /// Configuration for a Phase1 Ceremony large enough to support MantaPay circuits
    pub type SubCeremony = PerpetualPowersOfTauCeremony<PpotSerializer, POWERS>;

    /// Checks a transition between challenge files.  Note that the appropriate challenge
    /// and reponse files must belong to `manta-parameters`.
    #[ignore] // NOTE: Adds `ignore` such that CI does NOT run this test while still allowing developers to test.
    #[test]
    fn verify_one_transition_test() {
        use memmap::MmapOptions;
        use std::{fs::OpenOptions, time::Instant};

        // Read first accumulator
        println!("Reading accumulator from challenge file");
        let now = Instant::now();
        let reader = OpenOptions::new()
            .read(true)
            .open("../manta-parameters/data/ppot/challenge_0071.lfs") // TODO: This path doesn't work
            .expect("unable open `./challenge` in this directory");
        let challenge_map = unsafe {
            MmapOptions::new()
                .map(&reader)
                .expect("unable to create a memory map for input")
        };
        let prev_accumulator =
            read_subaccumulator::<SubCeremony>(&challenge_map, Compressed::No).unwrap();
        println!("Read uncompressed accumulator in {:?}", now.elapsed());

        // Read second accumulator
        println!("Reading accumulator from challenge file");
        let now = Instant::now();
        let reader = OpenOptions::new()
            .read(true)
            .open("../manta-parameters/data/ppot/challenge_0072.lfs")
            .expect("unable open `./challenge` in this directory");
        let challenge_map = unsafe {
            MmapOptions::new()
                .map(&reader)
                .expect("unable to create a memory map for input")
        };
        let next_accumulator =
            read_subaccumulator::<SubCeremony>(&challenge_map, Compressed::No).unwrap();
        println!("Read uncompressed accumulator in {:?}", now.elapsed());

        // Load `response` file
        println!("Reading accumulator from response file");
        let reader = OpenOptions::new()
            .read(true)
            .open("../manta-parameters/data/ppot/response_0071.lfs")
            .expect("unable open `./response` in this directory");
        let response = unsafe {
            MmapOptions::new()
                .map(&reader)
                .expect("unable to create a memory map for input")
        };

        let challenge_hash: [u8; 64] = into_array_unchecked(
            response
                .get(0..64)
                .expect("Cannot read hash from header of response file"),
        );
        let proof: Proof<PpotCeremony> = read_kzg_proof(&response).unwrap();

        let _prev = Accumulator::<SubCeremony>::verify_transform(
            prev_accumulator,
            next_accumulator,
            challenge_hash,
            proof.cast_to_subceremony(),
        )
        .unwrap();
    }
}
