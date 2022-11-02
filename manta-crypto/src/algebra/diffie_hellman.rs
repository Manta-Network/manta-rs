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

//! Diffie-Hellman Key Agreement Scheme

use crate::{
    algebra::{security, Group, HasGenerator, Ring, ScalarMul},
    eclair::alloc::Constant,
    key,
    rand::{RngCore, Sample},
};
use core::marker::PhantomData;
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Diffie-Hellmann Standard Mode
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Standard;

/// Standard Diffie-Hellman Key Agreement Scheme
pub type StandardDiffieHellman<S, G, GEN = G> = DiffieHellman<S, G, GEN, Standard>;

/// Diffie-Hellmann Known-Scalar Mode
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KnownScalar;

/// Known-Scalar Diffie-Hellman Key Agreement Scheme
pub type KnownScalarDiffieHellman<S, G, GEN = G> = DiffieHellman<S, G, GEN, KnownScalar>;

/// Diffie-Hellman Key Agreement Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiffieHellman<S, G, GEN = G, M = Standard> {
    /// Group Generator
    pub generator: GEN,

    /// Type Parameter Marker
    __: PhantomData<(S, G, M)>,
}

impl<S, G, GEN, M> DiffieHellman<S, G, GEN, M> {
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

impl<S, G, GEN, M, COM> Constant<COM> for DiffieHellman<S, G, GEN, M>
where
    S: Constant<COM>,
    G: Constant<COM>,
    GEN: Constant<COM>,
{
    type Type = DiffieHellman<S::Type, G::Type, GEN::Type, M>;

    #[inline]
    fn new_constant(value: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(Constant::new_constant(&value.generator, compiler))
    }
}

impl<S, G, GEN, M> Decode for DiffieHellman<S, G, GEN, M>
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

impl<S, G, GEN, M> Encode for DiffieHellman<S, G, GEN, M>
where
    GEN: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.generator.encode(&mut writer)
    }
}

impl<S, G, GEN, M, D> Sample<D> for DiffieHellman<S, G, GEN, M>
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

impl<S, G, GEN, M, COM> HasGenerator<G, COM> for DiffieHellman<S, G, GEN, M>
where
    G: Group<COM>,
{
    type Generator = GEN;

    #[inline]
    fn generator(&self) -> &Self::Generator {
        &self.generator
    }
}

impl<S, G, GEN> key::agreement::SecretKeyType for StandardDiffieHellman<S, G, GEN> {
    type SecretKey = S;
}

impl<S, G, GEN> key::agreement::EphemeralSecretKeyType for StandardDiffieHellman<S, G, GEN> {
    type EphemeralSecretKey = S;
}

impl<S, G, GEN> key::agreement::PublicKeyType for StandardDiffieHellman<S, G, GEN> {
    type PublicKey = G;
}

impl<S, G, GEN> key::agreement::EphemeralPublicKeyType for StandardDiffieHellman<S, G, GEN> {
    type EphemeralPublicKey = G;
}

impl<S, G, GEN> key::agreement::SharedSecretType for DiffieHellman<S, G, GEN, Standard> {
    type SharedSecret = G;
}

impl<S, G, GEN, COM> key::agreement::Derive<COM> for StandardDiffieHellman<S, G, GEN>
where
    GEN: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        self.generator.scalar_mul(secret_key, compiler)
    }
}

impl<S, G, GEN, COM> key::agreement::DeriveEphemeral<COM> for StandardDiffieHellman<S, G, GEN>
where
    GEN: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn derive_ephemeral(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::EphemeralPublicKey {
        self.generator.scalar_mul(ephemeral_secret_key, compiler)
    }
}

impl<S, G, GEN, COM> key::agreement::GenerateSecret<COM> for StandardDiffieHellman<S, G, GEN>
where
    G: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn generate_secret(
        &self,
        public_key: &Self::PublicKey,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        public_key.scalar_mul(ephemeral_secret_key, compiler)
    }
}

impl<S, G, GEN, COM> key::agreement::Agree<COM> for StandardDiffieHellman<S, G, GEN>
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

impl<S, G, GEN, COM> key::agreement::ReconstructSecret<COM> for StandardDiffieHellman<S, G, GEN>
where
    G: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn reconstruct_secret(
        &self,
        ephemeral_public_key: &Self::EphemeralPublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        ephemeral_public_key.scalar_mul(secret_key, compiler)
    }
}

impl<S, G, GEN> key::agreement::SecretKeyType for KnownScalarDiffieHellman<S, G, GEN> {
    type SecretKey = S;
}

impl<S, G, GEN> key::agreement::EphemeralSecretKeyType for KnownScalarDiffieHellman<S, G, GEN> {
    type EphemeralSecretKey = S;
}

impl<S, G, GEN> key::agreement::PublicKeyType for KnownScalarDiffieHellman<S, G, GEN> {
    type PublicKey = S;
}

impl<S, G, GEN> key::agreement::EphemeralPublicKeyType for KnownScalarDiffieHellman<S, G, GEN> {
    type EphemeralPublicKey = G;
}

impl<S, G, GEN> key::agreement::SharedSecretType for KnownScalarDiffieHellman<S, G, GEN> {
    type SharedSecret = G;
}

impl<S, G, GEN, COM> key::agreement::Derive<COM> for KnownScalarDiffieHellman<S, G, GEN>
where
    S: Clone,
{
    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        let _ = compiler;
        secret_key.clone()
    }
}

impl<S, G, GEN, COM> key::agreement::DeriveEphemeral<COM> for KnownScalarDiffieHellman<S, G, GEN>
where
    GEN: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn derive_ephemeral(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::EphemeralPublicKey {
        self.generator.scalar_mul(ephemeral_secret_key, compiler)
    }
}

impl<S, G, GEN, COM> key::agreement::GenerateSecret<COM> for KnownScalarDiffieHellman<S, G, GEN>
where
    GEN: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
    S: Ring<COM>,
{
    #[inline]
    fn generate_secret(
        &self,
        public_key: &Self::PublicKey,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        self.generator
            .scalar_mul(&public_key.mul(ephemeral_secret_key, compiler), compiler)
    }
}

impl<S, G, GEN, COM> key::agreement::Agree<COM> for KnownScalarDiffieHellman<S, G, GEN>
where
    GEN: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
    S: Ring<COM>,
{
    #[inline]
    fn agree(
        &self,
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        self.generator
            .scalar_mul(&public_key.mul(secret_key, compiler), compiler)
    }
}

impl<S, G, GEN, COM> key::agreement::ReconstructSecret<COM> for KnownScalarDiffieHellman<S, G, GEN>
where
    G: ScalarMul<S, COM, Output = G> + security::ComputationalDiffieHellmanHardness,
{
    #[inline]
    fn reconstruct_secret(
        &self,
        ephemeral_public_key: &Self::EphemeralPublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        ephemeral_public_key.scalar_mul(secret_key, compiler)
    }
}
