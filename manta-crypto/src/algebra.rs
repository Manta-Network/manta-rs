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
use alloc::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};
use manta_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    into_array_unchecked,
};

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
    /// Output Type
    type Output;

    /// Multiplies `self` by `scalar` in the group.
    fn scalar_mul(&self, scalar: &S, compiler: &mut COM) -> Self::Output;
}

/// Group with a Scalar Multiplication
pub trait ScalarMulGroup<S, COM = ()>: Group<COM> + ScalarMul<S, COM> {}

impl<G, S, COM> ScalarMulGroup<S, COM> for G where G: Group<COM> + ScalarMul<S, COM> {}

/// Group Generator
pub trait HasGenerator<G, COM = ()>
where
    G: Group<COM>,
{
    /// Generator Type
    type Generator;

    /// Returns a generator of `G`.
    fn generator(&self) -> &Self::Generator;
}

/// Fixed Base Scalar Multiplication using precomputed base points
pub trait FixedBaseScalarMul<COM = ()>: Group<COM> {
    /// Fixed Base Point
    type Base;

    /// Multiply `precomputed_bases[0]` by `scalar` using precomputed base points,
    /// where `precomputed_bases` are precomputed power-of-two multiples of the fixed base.  
    fn fixed_base_scalar_mul<I>(
        precomputed_bases: I,
        scalar: &Self::Scalar,
        compiler: &mut COM,
    ) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Base>;
}

/// Precomputed power-of-two Base for fixed-base scalar multiplication. Entry at index `i` is `base * 2^i`.
pub struct PrecomputedBaseTable<G, const N: usize> {
    table: [G; N],
}

impl<G, const N: usize> IntoIterator for PrecomputedBaseTable<G, N> {
    type Item = G;
    type IntoIter = core::array::IntoIter<G, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.table.into_iter()
    }
}

impl<G, const N: usize> PrecomputedBaseTable<G, N> {
    #[inline]
    /// Builds a new [`PrecomputedBaseTable`] from a given `base`, such that `table[i] = base * 2^i`.
    pub fn from_base<COM>(base: G, compiler: &mut COM) -> Self
    where
        G: Group<COM>,
    {
        let table = into_array_unchecked(
            core::iter::successors(Some(base), |base| Some(base.add(base, compiler)))
                .take(N)
                .collect::<Vec<_>>(),
        );
        Self { table }
    }
}

/// Diffie-Hellman Key Agreement Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiffieHellman<S, G, GEN = G> {
    /// Group Generator
    pub generator: GEN,

    /// Type Parameter Marker
    __: PhantomData<(S, G)>,
}

impl<S, G, GEN> DiffieHellman<S, G, GEN> {
    /// Builds a new [`DiffieHellman`] key agreement scheme from the given `generator`.
    #[inline]
    pub fn new(generator: GEN) -> Self {
        Self {
            generator,
            __: PhantomData,
        }
    }

    /// Converts `self` into the group generator.
    #[inline]
    pub fn into_inner(self) -> GEN {
        self.generator
    }
}

impl<S, G, GEN, COM> HasGenerator<G, COM> for DiffieHellman<S, G, GEN>
where
    G: Group<COM>,
{
    type Generator = GEN;

    #[inline]
    fn generator(&self) -> &Self::Generator {
        &self.generator
    }
}

impl<S, G, GEN, COM> Constant<COM> for DiffieHellman<S, G, GEN>
where
    S: Constant<COM>,
    G: Constant<COM>,
    GEN: Constant<COM>,
{
    type Type = DiffieHellman<S::Type, G::Type, GEN::Type>;

    #[inline]
    fn new_constant(value: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(Constant::new_constant(&value.generator, compiler))
    }
}

impl<S, G, GEN> key::agreement::Types for DiffieHellman<S, G, GEN> {
    type SecretKey = S;
    type PublicKey = G;
    type SharedSecret = G;
}

impl<S, G, GEN, COM> key::agreement::Derive<COM> for DiffieHellman<S, G, GEN>
where
    GEN: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        self.generator.scalar_mul(secret_key, compiler)
    }
}

impl<S, G, GEN, COM> key::agreement::Agree<COM> for DiffieHellman<S, G, GEN>
where
    G: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
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

impl<S, G, GEN> Decode for DiffieHellman<S, G, GEN>
where
    GEN: Decode,
{
    type Error = GEN::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(Decode::decode(&mut reader)?))
    }
}

impl<S, G, GEN> Encode for DiffieHellman<S, G, GEN>
where
    GEN: Encode,
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

impl<S, G, GEN, D> Sample<D> for DiffieHellman<S, G, GEN>
where
    GEN: Sample<D>,
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
/// types that implement [`ScalarMul`] for some set of scalars. These security properties can be
/// attached to instances of [`ScalarMul`] which we assume to have these hardness properties.
pub mod security {
    /// Discrete Logarithm Hardness Assumption
    ///
    /// For a type `G`, it should be infeasible to find a procedure `f` that makes this function
    /// return `true`:
    ///
    /// ```text
    /// fn solve<G, S, F>(g: G, y: S, f: F) -> bool
    /// where
    ///     G: ScalarMul<S>,
    ///     F: FnOnce(G, G) -> S,
    /// {
    ///     y == g.scalar_mul(f(g, y))
    /// }
    /// ```
    pub trait DiscreteLogarithmHardness {}

    /// Computational Diffie-Hellman Hardness Assumption
    ///
    /// For a type `G`, it should be infeasible to find a procedure `f` that makes this function
    /// return `true`:
    ///
    /// ```text
    /// fn solve<G, S, F>(g: G, a: S, b: S, f: F) -> bool
    /// where
    ///     G: ScalarMul<S>,
    ///     S: Ring,
    ///     F: FnOnce(G, G, G) -> G,
    /// {
    ///     f(g, g.scalar_mul(a), g.scalar_mul(b)) == g.scalar_mul(a.mul(b))
    /// }
    /// ```
    pub trait ComputationalDiffieHellmanHardness: DiscreteLogarithmHardness {}

    /// Decisional Diffie-Hellman Hardness Assumption
    ///
    /// For a type `G`, it should be infeasible to distinguish the probability distributions over
    /// the following two functions when scalar inputs are sampled uniformly from their domain (and
    /// `g` the generator is fixed):
    ///
    /// ```text
    /// fn dh_triple<G, S>(g: G, a: S, b: S) -> (G, G, G)
    /// where
    ///     G: ScalarMul<S>,
    ///     S: Ring,
    /// {
    ///     (g.scalar_mul(a), g.scalar_mul(b), g.scalar_mul(a.mul(b)))
    /// }
    ///
    /// fn random_triple<G, S>(g: G, a: S, b: S, c: S) -> (G, G, G)
    /// where
    ///     G: ScalarMul<S>,
    /// {
    ///     (g.scalar_mul(a), g.scalar_mul(b), g.scalar_mul(c))
    /// }
    /// ```
    pub trait DecisionalDiffieHellmanHardness: ComputationalDiffieHellmanHardness {}
}
