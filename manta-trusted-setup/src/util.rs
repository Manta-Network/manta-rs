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

//! Utilities

use crate::groth16::kzg;
use alloc::{boxed::Box, vec::Vec};
use ark_std::{
    error,
    io::{self, ErrorKind},
};
use blake2::{Blake2b512, Digest as Blake2Digest};
use core::marker::PhantomData;
use manta_crypto::{
    arkworks::{
        ec::{wnaf::WnafContext, AffineCurve, ProjectiveCurve},
        ff::{BigInteger, PrimeField, UniformRand, Zero},
        pairing::Pairing,
        ratio::HashToGroup,
        serialize::{CanonicalSerialize, Read, SerializationError, Write},
    },
    rand::{ChaCha20Rng, OsRng, Sample, SeedableRng},
};
use manta_util::{cfg_into_iter, cfg_iter, cfg_iter_mut, cfg_reduce, into_array_unchecked};

#[cfg(feature = "rayon")]
use manta_util::rayon::iter::{IndexedParallelIterator, ParallelIterator};

/// Distribution Type Extension
pub trait HasDistribution {
    /// Distribution Type
    type Distribution: Default;
}

/// Custom Serialization Adapter
///
/// In the majority of cases we can just use [`CanonicalSerialize`] and [`CanonicalDeserialize`] to
/// make data types compatible with the `arkworks` serialization system. However, in some cases we
/// need to provide a "non-canonical" serialization for an existing type. This `trait` provides an
/// interface for building a serialization over the type `T`. For deserialization see the
/// [`Deserializer`] `trait`.
///
/// [`CanonicalDeserialize`]: manta_crypto::arkworks::serialize::CanonicalDeserialize
pub trait Serializer<T, M = ()> {
    /// Serializes `item` in uncompressed form to the `writer` without performing any
    /// well-formedness checks.
    fn serialize_unchecked<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write;

    /// Serializes `item` in uncompressed form to the `writer`, performing all well-formedness
    /// checks.
    fn serialize_uncompressed<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write;

    /// Returns the size in bytes of the uncompressed form of `item`.
    fn uncompressed_size(item: &T) -> usize;

    /// Serializes `item` in compressed form to the `writer`, performing all well-formedness checks.
    fn serialize_compressed<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write;

    /// Returns the size in bytes of the compressed form of `item`.
    fn compressed_size(item: &T) -> usize;
}

/// Custom Deserialization Adapter
///
/// In the majority of cases we can just use [`CanonicalSerialize`] and [`CanonicalDeserialize`] to
/// make data types compatible with the `arkworks` serialization system. However, in some cases we
/// need to provide a "non-canonical" deserialization for an existing type. This `trait` provides an
/// interface for building a deserialization over the type `T`. For serialization see the
/// [`Serializer`] `trait`.
///
/// [`CanonicalDeserialize`]: manta_crypto::arkworks::serialize::CanonicalDeserialize
pub trait Deserializer<T, M = ()> {
    /// Deserialization Error Type
    type Error: Into<SerializationError>;

    /// Checks that `item` is a valid element of type `T`.
    ///
    /// # Implementation Note
    ///
    /// Implementing this method is optional and by default it does nothing since callers should
    /// always rely on the `deserialize_*` methods directly. However, the
    /// [`deserialize_uncompressed`] method calls this method, so if the difference between
    /// [`deserialize_unchecked`] and [`deserialize_uncompressed`] is just a simple check on the
    /// type `T`, then this function should be implemented. Otherwise, [`deserialize_uncompressed`]
    /// should be implemented manually.
    ///
    /// [`deserialize_uncompressed`]: Self::deserialize_uncompressed
    /// [`deserialize_unchecked`]: Self::deserialize_unchecked
    #[inline]
    fn check(item: &T) -> Result<(), Self::Error> {
        let _ = item;
        Ok(())
    }

    /// Deserializes a single uncompressed item of type `T` from the `reader` with the minimal
    /// amount of checks required to form the type.
    fn deserialize_unchecked<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read;

    /// Deserializes a single uncompressed item of type `T` from the `reader` with all validity
    /// checks enabled.
    ///
    /// # Implementation Note
    ///
    /// Implementing this method is optional whenever there exists a non-default implementation of
    /// [`check`](Self::check). See its documentation for more.
    #[inline]
    fn deserialize_uncompressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = Self::deserialize_unchecked(reader)?;
        Self::check(&item)?;
        Ok(item)
    }

    /// Deserializes a single compressed item of type `T` from the `reader` with all validity checks
    /// enabled.
    fn deserialize_compressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read;
}

/// Converts `err` into an [`io::Error`] with the [`ErrorKind::Other`] variant.
#[inline]
pub fn from_error<E>(err: E) -> io::Error
where
    E: Into<Box<dyn error::Error + Send + Sync>>,
{
    io::Error::new(ErrorKind::Other, err)
}

/// Deserialization Error for [`NonZero`]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NonZeroError<E> {
    /// Element was Zero when Deserialized
    IsZero,

    /// Other Deserialization Error
    Error(E),
}

impl<E> From<NonZeroError<E>> for SerializationError
where
    E: Into<SerializationError>,
{
    #[inline]
    fn from(err: NonZeroError<E>) -> Self {
        match err {
            NonZeroError::IsZero => from_error("Value was expected to be non-zero.").into(),
            NonZeroError::Error(err) => err.into(),
        }
    }
}

/// Non-Zero Checking Deserializer
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NonZero<D>(PhantomData<D>);

impl<D> NonZero<D> {
    /// Checks if `item` is zero, returning [`NonZeroError::IsZero`] if so.
    #[inline]
    fn is_zero<T, M>(item: &T) -> Result<(), NonZeroError<D::Error>>
    where
        D: Deserializer<T, M>,
        T: Zero,
    {
        if item.is_zero() {
            return Err(NonZeroError::IsZero);
        }
        Ok(())
    }
}

impl<T, M, D> Deserializer<T, M> for NonZero<D>
where
    D: Deserializer<T, M>,
    T: Zero,
{
    type Error = NonZeroError<D::Error>;

    #[inline]
    fn check(item: &T) -> Result<(), Self::Error> {
        Self::is_zero(item)?;
        D::check(item).map_err(Self::Error::Error)
    }

    #[inline]
    fn deserialize_unchecked<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = D::deserialize_unchecked(reader).map_err(Self::Error::Error)?;
        Self::is_zero(&item)?;
        Ok(item)
    }

    #[inline]
    fn deserialize_uncompressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = D::deserialize_uncompressed(reader).map_err(Self::Error::Error)?;
        Self::is_zero(&item)?;
        Ok(item)
    }

    #[inline]
    fn deserialize_compressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = D::deserialize_compressed(reader).map_err(Self::Error::Error)?;
        Self::is_zero(&item)?;
        Ok(item)
    }
}

/// Multiplies `point` by `scalar` in-place.
#[inline]
pub fn scalar_mul<G>(point: &mut G, scalar: G::ScalarField)
where
    G: AffineCurve,
{
    *point = point.mul(scalar).into_affine();
}

/// Converts each affine point in `points` into its projective form.
#[inline]
pub fn batch_into_projective<G>(points: &[G]) -> Vec<G::Projective>
where
    G: AffineCurve,
{
    cfg_iter!(points).map(G::into_projective).collect()
}

/// Returns the empirically-recommended window size for WNAF on the given `scalar`.
#[inline]
pub fn wnaf_empirical_recommended_window_size<F>(scalar: &F) -> usize
where
    F: BigInteger,
{
    let num_bits = scalar.num_bits() as usize;
    if num_bits >= 130 {
        4
    } else if num_bits >= 34 {
        3
    } else {
        2
    }
}

/// Returns a [`WnafContext`] with the empirically-recommended window size. See
/// [`wnaf_empirical_recommended_window_size`] for more.
#[inline]
pub fn recommended_wnaf<F>(scalar: &F) -> WnafContext
where
    F: PrimeField,
{
    WnafContext::new(wnaf_empirical_recommended_window_size(&scalar.into_repr()))
}

/// Compresses `lhs` and `rhs` into a pair of curve points by random linear combination. The same
/// random linear combination is used for both `lhs` and `rhs`, allowing this pair to be used in a
/// consistent ratio test.
#[inline]
pub fn merge_pairs_projective<G>(lhs: &[G], rhs: &[G]) -> (G, G)
where
    G: ProjectiveCurve,
{
    assert_eq!(lhs.len(), rhs.len());
    cfg_reduce!(
        cfg_into_iter!(0..lhs.len())
            .map(|_| G::ScalarField::rand(&mut OsRng))
            .zip(lhs)
            .zip(rhs)
            .map(|((rho, lhs), rhs)| {
                let wnaf = recommended_wnaf(&rho);
                (wnaf.mul(*lhs, &rho), wnaf.mul(*rhs, &rho))
            }),
        || (G::zero(), G::zero()),
        |mut acc, next| {
            acc.0 += next.0;
            acc.1 += next.1;
            acc
        }
    )
}

/// Compresses `lhs` and `rhs` into a pair of curve points by random linear combination. The same
/// random linear combination is used for both `lhs` and `rhs`, allowing this pair to be used in a
/// consistent ratio test.
#[inline]
pub fn merge_pairs_affine<G>(lhs: &[G], rhs: &[G]) -> (G, G)
where
    G: AffineCurve,
{
    assert_eq!(lhs.len(), rhs.len());
    cfg_reduce!(
        cfg_into_iter!(0..lhs.len())
            .map(|_| { G::ScalarField::rand(&mut OsRng) })
            .zip(lhs)
            .zip(rhs)
            .map(|((rho, lhs), rhs)| (lhs.mul(rho).into_affine(), rhs.mul(rho).into_affine())),
        || (Zero::zero(), Zero::zero()),
        |mut acc, next| {
            acc.0 = acc.0 + next.0;
            acc.1 = acc.1 + next.1;
            acc
        }
    )
}

/// Prepares a sequence of curve points for a check that subsequent terms differ by a constant ratio.
/// Concretely, this computes a random linear combination of all but the last point of the sequence
/// and the same linear combination of all but the first point of the sequence. The original check
/// reduces to checking that these linear combinations differ by the expected ratio.
#[inline]
pub fn power_pairs<G>(points: &[G]) -> (G, G)
where
    G: AffineCurve,
{
    let points_proj = batch_into_projective(points);
    let (g1_proj, g2_proj) =
        merge_pairs_projective(&points_proj[..(points_proj.len() - 1)], &points_proj[1..]);
    (g1_proj.into_affine(), g2_proj.into_affine())
}

/// Blake Hasher
#[derive(Default)]
pub struct BlakeHasher(pub Blake2b512);

impl Write for BlakeHasher {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<P, const N: usize> HashToGroup<P, [u8; N]> for BlakeHasher
where
    P: Pairing,
    P::G2: Sample,
{
    #[inline]
    fn hash(&self, challenge: &[u8; N], ratio: (&P::G1, &P::G1)) -> P::G2 {
        let mut hasher = BlakeHasher::default();
        hasher.0.update(challenge);
        ratio.0.serialize(&mut hasher).unwrap();
        ratio.1.serialize(&mut hasher).unwrap();
        hash_to_group::<_, (), 64>(into_array_unchecked(hasher.0.finalize()))
    }
}

/// KZG Blake Hasher
pub struct KZGBlakeHasher<C>
where
    C: kzg::Configuration + ?Sized,
{
    /// Domain Tag Type
    pub domain_tag: C::DomainTag,
}

impl<P, const N: usize> HashToGroup<P, [u8; N]> for KZGBlakeHasher<P>
where
    P: kzg::Configuration<DomainTag = u8> + ?Sized,
    P::G2: Sample,
{
    #[inline]
    fn hash(&self, challenge: &[u8; N], ratio: (&P::G1, &P::G1)) -> P::G2 {
        let mut hasher = BlakeHasher::default();
        hasher.0.update([self.domain_tag]);
        hasher.0.update(challenge);
        ratio.0.serialize(&mut hasher).unwrap();
        ratio.1.serialize(&mut hasher).unwrap();
        hash_to_group::<_, (), 64>(into_array_unchecked(hasher.0.finalize()))
    }
}

/// Consumes `digest` as a seed to an RNG and use the RNG to sample a group point `G`
/// on affine curve.
#[inline]
pub fn hash_to_group<G, D, const N: usize>(digest: [u8; N]) -> G
where
    G: AffineCurve + Sample<D>,
    D: Default,
{
    assert!(N >= 32, "Needs at least 32 bytes to seed ChaCha20.");
    let mut digest = digest.as_slice();
    let mut seed = Vec::<u8>::with_capacity(32);
    for _ in 0..8 {
        let mut buffer = [0u8; 4];
        let _ = digest
            .read(&mut buffer)
            .expect("Reading into a slice never fails.");
        seed.extend(buffer.iter().rev());
    }
    G::gen(&mut ChaCha20Rng::from_seed(into_array_unchecked(seed)))
}

/// Multiplies each element in `bases` by a fixed `scalar`.
#[inline]
pub fn batch_mul_fixed_scalar<G>(points: &mut [G], scalar: G::ScalarField)
where
    G: AffineCurve,
{
    cfg_iter_mut!(points).for_each(|point| scalar_mul(point, scalar))
}

/// Pointwise multiplication of a vector of `points` and a vector of `scalars`.
#[inline]
pub fn batch_mul_pointwise<G>(points: &mut [G], scalars: &[G::ScalarField])
where
    G: ProjectiveCurve,
{
    assert_eq!(
        points.len(),
        scalars.len(),
        "Points should have the same length as scalars."
    );
    cfg_iter_mut!(points)
        .zip(cfg_iter!(scalars))
        .for_each(|(base, scalar)| {
            base.mul_assign(*scalar);
        })
}
