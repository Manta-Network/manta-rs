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

use alloc::vec::Vec;
use ark_ec::{wnaf::WnafContext, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::io;
use core::{iter, marker::PhantomData};
use manta_crypto::rand::OsRng;
use manta_util::{cfg_into_iter, cfg_iter, cfg_iter_mut, cfg_reduce};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use blake2::{Blake2b, digest::consts::U8};

#[cfg(feature = "rayon")]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};

pub use ark_ff::{One, Zero};
pub use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};
pub use manta_crypto::rand::Sample;

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
/// [`CanonicalSerialize`]: ark_serialize::CanonicalSerialize
/// [`CanonicalDeserialize`]: ark_serialize::CanonicalDeserialize
pub trait Serializer<T> {
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
/// [`CanonicalSerialize`]: ark_serialize::CanonicalSerialize
/// [`CanonicalDeserialize`]: ark_serialize::CanonicalDeserialize
pub trait Deserializer<T> {
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
            NonZeroError::IsZero => SerializationError::IoError(io::Error::new(
                io::ErrorKind::Other,
                "Value was expected to be non-zero but instead had value zero.",
            )),
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
    fn is_zero<T>(item: &T) -> Result<(), NonZeroError<D::Error>>
    where
        D: Deserializer<T>,
        T: Zero,
    {
        if item.is_zero() {
            return Err(NonZeroError::IsZero);
        }
        Ok(())
    }
}

impl<T, D> Deserializer<T> for NonZero<D>
where
    D: Deserializer<T>,
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
    let pairs = cfg_into_iter!(0..lhs.len())
        .map(|_| G::ScalarField::rand(&mut OsRng))
        .zip(lhs)
        .zip(rhs)
        .map(|((rho, lhs), rhs)| {
            let wnaf = recommended_wnaf(&rho);
            (wnaf.mul(*lhs, &rho), wnaf.mul(*rhs, &rho))
        });
    cfg_reduce!(pairs, || (G::zero(), G::zero()), |mut acc, next| {
        acc.0 += next.0;
        acc.1 += next.1;
        acc
    })
}

/// Compresses `lhs` and `rhs` into a pair of curve points by random linear combination. The same
/// random linear combination is used for both `lhs` and `rhs`, allowing this pair to be used in a
/// consistent ratio test.
#[inline]
pub fn merge_pairs_affine<G>(lhs: &[G], rhs: &[G]) -> (G::Projective, G::Projective)
where
    G: AffineCurve,
{
    assert_eq!(lhs.len(), rhs.len());
    let pairs = cfg_into_iter!(0..lhs.len())
        .map(|_| G::ScalarField::rand(&mut OsRng))
        .zip(lhs)
        .zip(rhs)
        .map(|((rho, lhs), rhs)| (lhs.mul(rho), rhs.mul(rho))); // TODO
    cfg_reduce!(pairs, || (Zero::zero(), Zero::zero()), |mut acc, next| {
        acc.0 += next.0;
        acc.1 += next.1;
        acc
    })
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

/// Pair from a [`PairingEngine`]
type Pair<P> = (
    <P as PairingEngine>::G1Prepared,
    <P as PairingEngine>::G2Prepared,
);

/// Pairing Engine Extension
pub trait PairingEngineExt: PairingEngine {
    /// Evaluates the pairing function on `pair`.
    #[inline]
    fn eval(pair: &Pair<Self>) -> Self::Fqk {
        Self::product_of_pairings(iter::once(pair))
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function.
    #[inline]
    fn has_same(lhs: &Pair<Self>, rhs: &Pair<Self>) -> bool {
        Self::eval(lhs) == Self::eval(rhs)
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function, returning
    /// `Some` with prepared points if the pairing outcome is the same. This function checks if
    /// there exists an `r` such that `(r * lhs.0 == rhs.0) && (lhs.1 == r * rhs.1)`.
    #[inline]
    fn same<L1, L2, R1, R2>(lhs: (L1, L2), rhs: (R1, R2)) -> Option<(Pair<Self>, Pair<Self>)>
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        let lhs = (lhs.0.into(), lhs.1.into());
        let rhs = (rhs.0.into(), rhs.1.into());
        Self::has_same(&lhs, &rhs).then(|| (lhs, rhs))
    }

    /// Checks if the ratio of `(lhs.0, lhs.1)` from `G1` is the same as the ratio of
    /// `(lhs.0, lhs.1)` from `G2`.
    #[inline]
    fn same_ratio<L1, L2, R1, R2>(lhs: (L1, R1), rhs: (L2, R2)) -> bool
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        Self::has_same(&(lhs.0.into(), rhs.1.into()), &(lhs.1.into(), rhs.0.into()))
    }
}

impl<E> PairingEngineExt for E where E: PairingEngine {}

/// Convenience wrapper trait covering functionality of cryptographic hash functions with fixed output size.
pub trait Digest<const N: usize> {
    /// TODO
    fn new() -> Self;
    /// TODO
    fn update(&mut self, data: impl AsRef<[u8]>);
    /// TODO
    fn finalize(self) -> [u8; N];
}

/// TODO: Add doc; update Size U8
pub struct BlakeHasher(Blake2b<U8>);

impl<const N: usize> Digest<N> for BlakeHasher {
    fn new() -> Self {
        BlakeHasher(Blake2b::default())
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        todo!()
    }

    fn finalize(self) -> [u8; N] {
        todo!()
    }
}

impl Write for BlakeHasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> io::Result<()> {
        todo!()
    }
}


/// TODO
pub fn hash_to_group<G, D, const N: usize>(digest: [u8; N]) -> G
where
    G: AffineCurve + Sample<D>,
    D: Default,
{
    let mut digest = digest.as_slice();
    let mut seed = Vec::with_capacity(8);
    for _ in 0..8 {
        let mut le_bytes = [0u8; 8];
        let word = digest
            .read(&mut le_bytes[..])
            .expect("This is always possible since we have enough bytes to begin with.");
        seed.extend(word.to_le_bytes());
    }
    G::gen(&mut ChaCha20Rng::from_seed(into_array_unchecked(seed)))
}

/// Performs the [`TryInto`] conversion into an array without checking if the conversion succeeded.
#[inline]
pub fn into_array_unchecked<T, V, const N: usize>(value: V) -> [T; N]
where
    V: TryInto<[T; N]>,
{
    match value.try_into() {
        Ok(array) => array,
        _ => unreachable!(
            "{} {:?}.",
            "Input did not have the correct length to match the output array of length", N
        ),
    }
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
    assert_eq!(points.len(), scalars.len(), "Points should have the same length as scalars.");
    cfg_iter_mut!(points)
        .zip(cfg_iter!(scalars))
        .for_each(|(base, scalar)| {
            base.mul_assign(*scalar);
        })
}