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

//! Signature Schemes

use crate::{
    constraint::{Add, Mul, Native, Sub},
    ecc::ScalarMul,
    hash::BinaryHashFunction,
};
use core::marker::PhantomData;

/// Signature Scheme
pub trait SignatureScheme<COM = ()> {
    /// Secret Key Type
    type SecretKey: ?Sized;

    /// Public Key Type
    type PublicKey;

    /// Message Type
    type Message: ?Sized;

    /// Signature Type
    type Signature;

    /// Derives a key of type [`PublicKey`](Self::PublicKey) from a key of type [`SecretKey`](Self::SecretKey) in `compiler`.
    fn derive_in(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey;

    /// Derives a key of type [`PublicKey`](Self::PublicKey) from a key of type [`SecretKey`](Self::SecretKey).
    fn derive(&self, secret_key: &Self::SecretKey) -> Self::PublicKey
    where
        COM: Native,
    {
        self.derive_in(secret_key, &mut COM::compiler())
    }

    /// Derives a key of type [`PublicKey`](Self::PublicKey) from a key of type [`SecretKey`](Self::SecretKey) in `compiler`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`derive_in`] when the `secret_key` value
    /// is owned, and by default, [`derive_in`] is used as its implementation. This
    /// method must return the same value as [`derive_in`] on the same input.
    ///
    /// [`derive_in`]: Self::derive_in
    #[inline]
    fn derive_owned_in(&self, secret_key: Self::SecretKey, compiler: &mut COM) -> Self::PublicKey
    where
        Self::SecretKey: Sized,
    {
        self.derive_in(&secret_key, compiler)
    }

    /// Derives a key of type [`PublicKey`](Self::PublicKey) from a key of type [`SecretKey`](Self::SecretKey).
    ///
    /// # Implementation Note
    ///
    /// See [`derive_owned_in`](Self::derive_owned_in) for more.
    #[inline]
    fn derive_owned(&self, key: Self::SecretKey) -> Self::PublicKey
    where
        COM: Native,
        Self::SecretKey: Sized,
    {
        self.derive_in(&key, &mut COM::compiler())
    }

    /// Signs a message of type [`Message`](Self::Message) with `key` in `compiler`.
    fn sign_in(
        &self,
        ephemeral_secret_key: &Self::SecretKey,
        key: &Self::SecretKey,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature;

    /// Signs a message of type [`Message`](Self::Message) with `key`.
    #[inline]
    fn sign(
        &self,
        ephemeral_secret_key: &Self::SecretKey,
        key: &Self::SecretKey,
        message: &Self::Message,
    ) -> Self::Signature
    where
        COM: Native,
    {
        self.sign_in(ephemeral_secret_key, key, message, &mut COM::compiler())
    }

    /// Signs a message of type [`Message`](Self::Message) with `key` in `compiler`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`sign_in`] when the `key` value
    /// is owned, and by default, [`sign_in`] is used as its implementation. This
    /// method must return the same value as [`sign_in`] on the same input.
    ///
    /// [`sign_in`]: Self::sign_in
    #[inline]
    fn sign_owned_in(
        &self,
        ephemeral_secret_key: &Self::SecretKey,
        key: Self::SecretKey,
        message: Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature
    where
        Self::Message: Sized,
        Self::SecretKey: Sized,
    {
        self.sign_in(&ephemeral_secret_key, &key, &message, compiler)
    }

    /// Signs a message of type [`Message`](Self::Message) with `key`.
    ///
    /// # Implementation Note
    ///
    /// See [`sign_owned_in`](Self::sign_owned_in) for more.
    #[inline]
    fn sign_owned(
        &self,
        ephemeral_secret_key: Self::SecretKey,
        key: Self::SecretKey,
        message: Self::Message,
    ) -> Self::Signature
    where
        COM: Native,
        Self::Message: Sized,
        Self::SecretKey: Sized,
    {
        self.sign_in(&ephemeral_secret_key, &key, &message, &mut COM::compiler())
    }

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message` in `compiler`.
    fn verify_in(
        &self,
        public_key: &Self::PublicKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> bool;

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message`.
    #[inline]
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &Self::Message,
        signature: &Self::Signature,
    ) -> bool
    where
        COM: Native,
    {
        self.verify_in(public_key, message, signature, &mut COM::compiler())
    }

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message` in `compiler`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`verify_in`] when the `key` value is
    /// owned, and by default, [`verify_in`] is used as its implementation. This method
    /// must return the same value as [`verify_in`] on the same input.
    ///
    /// [`verify_in`]: Self::verify_in
    #[inline]
    fn verify_owned_in(
        &self,
        public_key: Self::PublicKey,
        message: Self::Message,
        signature: Self::Signature,
        compiler: &mut COM,
    ) -> bool
    where
        Self::Message: Sized,
    {
        self.verify_in(&public_key, &message, &signature, compiler)
    }

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message`.
    ///
    /// See [`verify_in`](Self::verify_in) for more.
    #[inline]
    fn verify_owned(
        &self,
        public_key: Self::PublicKey,
        message: Self::Message,
        signature: Self::Signature,
    ) -> bool
    where
        COM: Native,
        Self::Message: Sized,
    {
        self.verify_in(&public_key, &message, &signature, &mut COM::compiler())
    }
}

/// Schnorr Signature
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Schnorr<G, H, SK, COM = ()> {
    /// Base Generator
    generator: G,

    /// Cryptographic Hash Function
    hasher: H,

    /// Private Signing Key
    signing_key: SK,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<G, H, SK, COM> SignatureScheme<COM> for Schnorr<G, H, SK, COM>
where
    G: Add<COM> + ScalarMul<COM, Output = G>,
    G::Scalar: Clone + Sub<COM> + Mul<COM> + PartialEq,
    G::Output: ScalarMul<COM>,
    H: BinaryHashFunction<COM, Left = G::Output, Output = G::Scalar>,
{
    type SecretKey = G::Scalar;

    type PublicKey = G::Output;

    type Message = H::Right;

    type Signature = (G::Scalar, G::Scalar);

    fn derive_in(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        self.generator.scalar_mul(secret_key, compiler)
    }

    fn sign_in(
        &self,
        ephemeral_secret_key: &Self::SecretKey,
        key: &Self::SecretKey,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature {
        let ephemeral_public_key = self.derive_in(ephemeral_secret_key, compiler);
        let hash_value = self
            .hasher
            .hash_in(&ephemeral_public_key, message, compiler);
        let s = G::Scalar::sub(
            ephemeral_secret_key.clone(),
            G::Scalar::mul(key.clone(), hash_value.clone(), compiler),
            compiler,
        );
        (s, hash_value)
    }

    fn verify_in(
        &self,
        public_key: &Self::PublicKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> bool {
        signature.1
            == self.hasher.hash_in(
                &G::add(
                    self.generator.scalar_mul(&signature.0, compiler),
                    public_key.scalar_mul(&signature.1, compiler),
                    compiler,
                ),
                message,
                compiler,
            )
    }
}
