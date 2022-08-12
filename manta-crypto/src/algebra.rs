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

//! Algebraic Constructions

use crate::{
    eclair::alloc::Constant,
    key,
    rand::{RngCore, Sample},
};
use core::marker::PhantomData;
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Group
pub trait Group<COM = ()> {
    /// Adds `rhs` to `self` in the group.
    fn add(&self, rhs: &Self, compiler: &mut COM) -> Self;
}

/// Ring
pub trait Ring<COM = ()>: Group<COM> {
    /// Multiplies `self` by `rhs` in the ring.
    fn mul(&self, rhs: &Self, compiler: &mut COM) -> Self;
}

/// Scalar Multiplication
pub trait ScalarMul<S, COM = ()> {
    /// Multiplies `self` by `scalar` in the group.
    fn scalar_mul(&self, scalar: &S, compiler: &mut COM) -> Self;
}

/// Group with a Scalar Multiplication
pub trait ScalarMulGroup<S, COM = ()>: Group<COM> + ScalarMul<S, COM> {}

impl<G, S, COM> ScalarMulGroup<S, COM> for G where G: Group<COM> + ScalarMul<S, COM> {}

/// Group Generator
pub trait HasGenerator<G, COM = ()>
where
    G: Group<COM>,
{
    /// Returns a generator of `G`.
    fn generator(&self) -> &G;
}

/// Diffie-Hellman Key Agreement Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiffieHellman<S, G> {
    /// Group Generator
    pub generator: G,

    /// Type Parameter Marker
    __: PhantomData<S>,
}

impl<S, G> DiffieHellman<S, G> {
    /// Builds a new [`DiffieHellman`] key agreement scheme from the given `generator`.
    #[inline]
    pub fn new(generator: G) -> Self {
        Self {
            generator,
            __: PhantomData,
        }
    }

    /// Converts `self` into the group generator.
    #[inline]
    pub fn into_inner(self) -> G {
        self.generator
    }
}

impl<S, G, COM> HasGenerator<G, COM> for DiffieHellman<S, G>
where
    G: Group<COM>,
{
    #[inline]
    fn generator(&self) -> &G {
        &self.generator
    }
}

impl<S, G, COM> Constant<COM> for DiffieHellman<S, G>
where
    S: Constant<COM>,
    G: Constant<COM>,
{
    type Type = DiffieHellman<S::Type, G::Type>;

    #[inline]
    fn new_constant(value: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(G::new_constant(&value.generator, compiler))
    }
}

impl<S, G> key::agreement::Types for DiffieHellman<S, G> {
    type SecretKey = S;
    type PublicKey = G;
    type SharedSecret = G;
}

impl<S, G, COM> key::agreement::Derive<COM> for DiffieHellman<S, G>
where
    G: ScalarMul<S, COM> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        self.generator.scalar_mul(secret_key, compiler)
    }
}

impl<S, G, COM> key::agreement::Agree<COM> for DiffieHellman<S, G>
where
    G: ScalarMul<S, COM> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn agree(
        &self,
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        public_key.scalar_mul(secret_key, compiler)
    }
}

impl<S, G> Decode for DiffieHellman<S, G>
where
    G: Decode,
{
    type Error = G::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(Decode::decode(&mut reader)?))
    }
}

impl<S, G> Encode for DiffieHellman<S, G>
where
    G: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.generator.encode(&mut writer)?;
        Ok(())
    }
}

impl<S, G, D> Sample<D> for DiffieHellman<S, G>
where
    G: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(Sample::sample(distribution, rng))
    }
}

/// Security Assumptions
///
/// The following outlines some standard security assumptions for cryptographic protocols built on
/// [`Group`] types. These security properties can be attached to instances of [`Group`] which we
/// assume to have these hardness properties.
pub mod security {
    /// Discrete Logarithm Hardness Assumption
    ///
    /// For a [`Group`](super::Group) `G`, it should be infeasible to find a procedure `f` that
    /// makes this function return `true`:
    ///
    /// ```text
    /// fn solve<F>(g: G, y: G, f: F) -> bool
    /// where
    ///     F: FnOnce(G, G) -> G::Scalar,
    /// {
    ///     y == g.mul(f(g, y))
    /// }
    /// ```
    pub trait DiscreteLogarithmHardness {}

    /// Computational Diffie-Hellman Hardness Assumption
    ///
    /// For a [`Group`](super::Group) `G`, it should be infeasible to find a procedure `f` that
    /// makes this function return `true`:
    ///
    /// ```text
    /// fn solve<F>(g: G, a: G::Scalar, b: G::Scalar, f: F) -> bool
    /// where
    ///     F: FnOnce(G, G, G) -> G,
    /// {
    ///     f(g, g.mul(a), g.mul(b)) == g.mul(a.mul(b))
    /// }
    /// ```
    pub trait ComputationalDiffieHellmanHardness: DiscreteLogarithmHardness {}

    /// Decisional Diffie-Hellman Hardness Assumption
    ///
    /// For a [`Group`](super::Group) `G`, it should be infeasible to distinguish the probability
    /// distributions over the following two functions when [`G::Scalar](super::Group::Scalar)
    /// inputs are sampled uniformly from their domain (and `g` the generator is fixed):
    ///
    /// ```text
    /// fn dh_triple(g: G, a: G::Scalar, b: G::Scalar) -> (G, G, G) {
    ///     (g.mul(a), g.mul(b), g.mul(a.mul(b)))
    /// }
    ///
    /// fn random_triple(g: G, a: G::Scalar, b: G::Scalar, c: G::Scalar) -> (G, G, G) {
    ///     (g.mul(a), g.mul(b), g.mul(c))
    /// }
    /// ```
    pub trait DecisionalDiffieHellmanHardness: ComputationalDiffieHellmanHardness {}
}
