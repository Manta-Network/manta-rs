// Copyright 2019-2021 Manta Network.
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

// TODO: Improve ECC abstractions over arkworks.

use crate::{
    constraint::Constant,
    key::KeyAgreementScheme,
    rand::{CryptoRng, RngCore, Sample},
};
use core::marker::PhantomData;

/// Elliptic Curve Group
pub trait Group<COM = ()>: Sized {
    /// Scalar Field
    type Scalar;

    /// Adds `rhs` to `self` in `compiler`, returning a new group element.
    #[must_use]
    fn add(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Adds an owned `rhs` value to `self` in `compiler`, returning a new group element.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`add`](Self::add) whenever operating with owned
    /// values is more efficient than with shared references.
    #[inline]
    #[must_use]
    fn add_owned(self, rhs: Self, compiler: &mut COM) -> Self {
        self.add(&rhs, compiler)
    }

    /// Multiplies `self` by `scalar` in `compiler`, returning a new group element.
    #[must_use]
    fn scalar_mul(&self, scalar: &Self::Scalar, compiler: &mut COM) -> Self;
}

/// Elliptic-Curve Diffie Hellman Key Exchange
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DiffieHellman<G, COM = ()>
where
    G: Group<COM>,
{
    /// Base Generator
    generator: G,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<G, COM> DiffieHellman<G, COM>
where
    G: Group<COM>,
{
    /// Builds a new [`DiffieHellman`] protocol structure from `generator`.
    #[inline]
    pub fn new(generator: G) -> Self {
        Self {
            generator,
            __: PhantomData,
        }
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

impl<G, COM> Constant<COM> for DiffieHellman<G, COM>
where
    G: Group<COM> + Constant<COM>,
    G::Type: Group,
{
    type Type = DiffieHellman<G::Type>;

    #[inline]
    fn new_constant(value: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(G::new_constant(&value.generator, compiler))
    }
}

impl<G, COM> KeyAgreementScheme<COM> for DiffieHellman<G, COM>
where
    G: Group<COM>,
{
    type SecretKey = G::Scalar;

    type PublicKey = G;

    type SharedSecret = G;

    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        self.agree(secret_key, &self.generator, compiler)
    }

    #[inline]
    fn agree(
        &self,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        public_key.scalar_mul(secret_key, compiler)
    }
}

impl<D, G, COM> Sample<D> for DiffieHellman<G, COM>
where
    G: Group<COM> + Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::new(G::sample(distribution, rng))
    }
}
