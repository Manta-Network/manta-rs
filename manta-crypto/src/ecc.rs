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

//! Elliptic Curve Cryptography

// TODO: Make sure we can use `PreprocessedScalarMulTable<G, _>` as a drop-in replacement for `G`.

use crate::{
    constraint::Constant,
    key::KeyAgreementScheme,
    rand::{CryptoRng, RngCore, Sample},
};
use alloc::{boxed::Box, vec::Vec};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    BoxArray,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Elliptic Curve Point Doubling Operation
pub trait PointDouble<COM = ()> {
    /// Output Type
    type Output;

    /// Performs a point doubling of `self` in `compiler`.
    #[must_use]
    fn double(&self, compiler: &mut COM) -> Self::Output;

    /// Performs a point doubling of `self` in `compiler` using an owned value.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`double`](Self::double) whenever operating with
    /// owned values is more efficient than with shared references.
    #[inline]
    fn double_owned(self, compiler: &mut COM) -> Self::Output
    where
        Self: Sized,
    {
        self.double(compiler)
    }

    /// Performs a point doubling of `self` in `compiler`, modifying `self` in-place.
    #[inline]
    fn double_assign(&mut self, compiler: &mut COM)
    where
        Self: PointDouble<COM, Output = Self> + Sized,
    {
        *self = self.double(compiler);
    }
}

/// Elliptic Curve Point Addition Operation
pub trait PointAdd<COM = ()> {
    /// Output Type
    type Output;

    /// Adds `rhs` to `self` in `compiler`, returning a new group element.
    #[must_use]
    fn add(&self, rhs: &Self, compiler: &mut COM) -> Self::Output;

    /// Adds an owned `rhs` value to `self` in `compiler`, returning a new group element.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`add`](Self::add) whenever operating with owned
    /// values is more efficient than with shared references.
    #[inline]
    fn add_owned(self, rhs: Self, compiler: &mut COM) -> Self::Output
    where
        Self: Sized,
    {
        self.add(&rhs, compiler)
    }

    /// Adds `rhs` to `self` in `compiler`, modifying `self` in-place.
    #[inline]
    fn add_assign(&mut self, rhs: &Self, compiler: &mut COM)
    where
        Self: PointAdd<COM, Output = Self> + Sized,
    {
        *self = self.add(rhs, compiler);
    }
}

/// Elliptic Curve Scalar Multiplication Operation
pub trait ScalarMul<COM = ()> {
    /// Scalar Field
    type Scalar;

    /// Output Type
    type Output;

    /// Multiplies `self` by `scalar` in `compiler`, returning a new group element.
    #[must_use]
    fn scalar_mul(&self, scalar: &Self::Scalar, compiler: &mut COM) -> Self::Output;

    /// Multiplies an owned `scalar` value to `self` in `compiler`, returning a new group element.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`scalar_mul`](Self::scalar_mul) whenever operating
    /// with owned values is more efficient than with shared references.
    #[inline]
    fn scalar_mul_owned(self, scalar: Self::Scalar, compiler: &mut COM) -> Self::Output
    where
        Self: Sized,
    {
        self.scalar_mul(&scalar, compiler)
    }

    /// Multiplies `self` by `scalar` in `compiler`, modifying `self` in-place.
    #[inline]
    fn scalar_mul_assign(&mut self, scalar: &Self::Scalar, compiler: &mut COM)
    where
        Self: ScalarMul<COM, Output = Self> + Sized,
    {
        *self = self.scalar_mul(scalar, compiler);
    }
}

/// Elliptic Curve Pre-processed Scalar Multiplication Operation
pub trait PreprocessedScalarMul<COM, const N: usize>: ScalarMul<COM> + Sized {
    /// Performs the scalar multiplication against a pre-computed table.
    ///
    /// The pre-computed table is a list of power-of-two multiples of `scalar`, such that
    /// `table[i] = scalar * 2^i`.
    #[must_use]
    fn preprocessed_scalar_mul(
        table: &[Self; N],
        scalar: &Self::Scalar,
        compiler: &mut COM,
    ) -> Self::Output;
}

impl<G, COM> PreprocessedScalarMul<COM, 1> for G
where
    G: ScalarMul<COM>,
{
    #[inline]
    fn preprocessed_scalar_mul(
        table: &[Self; 1],
        scalar: &Self::Scalar,
        compiler: &mut COM,
    ) -> Self::Output {
        table[0].scalar_mul(scalar, compiler)
    }
}

/// Elliptic Curve Group
pub trait Group<COM = ()>: PointAdd<COM> + PointDouble<COM> + ScalarMul<COM> {}

/// Pre-processed Scalar Multiplication Table
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "G: Deserialize<'de>", serialize = "G: Serialize"),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PreprocessedScalarMulTable<G, const N: usize> {
    /// Pre-computed Table
    table: BoxArray<G, N>,
}

impl<G, const N: usize> PreprocessedScalarMulTable<G, N> {
    /// Builds a new [`PreprocessedScalarMulTable`] collection from `base`.
    #[inline]
    pub fn from_base<COM>(mut base: G, compiler: &mut COM) -> Self
    where
        G: Clone + PointAdd<COM, Output = G> + PointDouble<COM, Output = G>,
    {
        let mut powers = Vec::with_capacity(N);
        let double = base.double(compiler);
        for _ in 0..N {
            powers.push(base.clone());
            base.add_assign(&double, compiler);
        }
        Self::from_powers_unchecked(
            powers
                .into_boxed_slice()
                .try_into()
                .ok()
                .expect("The size is correct because we perform `N` insertions."),
        )
    }

    /// Builds a new [`PreprocessedScalarMulTable`] collection from a known `table` set without
    /// checking if the table is consistent.
    #[inline]
    pub fn from_powers_unchecked(table: Box<[G; N]>) -> Self {
        Self {
            table: BoxArray(table),
        }
    }
}

impl<G, const N: usize> AsRef<[G; N]> for PreprocessedScalarMulTable<G, N> {
    #[inline]
    fn as_ref(&self) -> &[G; N] {
        &self.table
    }
}

impl<D, G, const N: usize> Sample<D> for PreprocessedScalarMulTable<G, N>
where
    G: Clone + PointAdd<Output = G> + PointDouble<Output = G> + Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::from_base(G::sample(distribution, rng), &mut ())
    }
}

impl<G, COM, const N: usize> ScalarMul<COM> for PreprocessedScalarMulTable<G, N>
where
    G: PreprocessedScalarMul<COM, N>,
{
    type Scalar = G::Scalar;
    type Output = G::Output;

    #[inline]
    fn scalar_mul(&self, scalar: &Self::Scalar, compiler: &mut COM) -> Self::Output {
        G::preprocessed_scalar_mul(&self.table, scalar, compiler)
    }
}

/// Elliptic-Curve Diffie Hellman Key Exchange
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DiffieHellman<G> {
    /// Base Generator
    generator: G,
}

impl<G> DiffieHellman<G> {
    /// Builds a new [`DiffieHellman`] protocol structure from `generator`.
    #[inline]
    pub fn new(generator: G) -> Self {
        Self { generator }
    }

    /// Returns a shared reference to the generator for this protocol.
    #[inline]
    pub fn generator(&self) -> &G {
        &self.generator
    }

    /// Converts `self` into its underlying generator.
    #[inline]
    pub fn into_generator(self) -> G {
        self.generator
    }
}

impl<G, COM> Constant<COM> for DiffieHellman<G>
where
    G: Constant<COM>,
{
    type Type = DiffieHellman<G::Type>;

    #[inline]
    fn new_constant(value: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(G::new_constant(&value.generator, compiler))
    }
}

impl<G> Decode for DiffieHellman<G>
where
    G: Decode,
{
    type Error = G::Error;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(G::decode(reader)?))
    }
}

impl<G> Encode for DiffieHellman<G>
where
    G: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.generator.encode(writer)
    }
}

impl<G, COM> KeyAgreementScheme<COM> for DiffieHellman<G>
where
    G: ScalarMul<COM>,
    G::Output: ScalarMul<COM, Scalar = G::Scalar, Output = G::Output>,
{
    type SecretKey = G::Scalar;
    type PublicKey = G::Output;
    type SharedSecret = G::Output;

    #[inline]
    fn derive_in(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        self.generator.scalar_mul(secret_key, compiler)
    }

    #[inline]
    fn agree_in(
        &self,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        public_key.scalar_mul(secret_key, compiler)
    }
}

impl<D, G> Sample<D> for DiffieHellman<G>
where
    G: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::new(G::sample(distribution, rng))
    }
}
