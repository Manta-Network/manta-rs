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

use crate::constraint::Native;

/// Signature Scheme Types
pub trait Types {
    /// Randomness Type
    type Randomness: ?Sized;

    /// Signing Key Type
    type SigningKey: ?Sized;

    /// Verifying Key Type
    type VerifyingKey;

    /// Message Type
    type Message: ?Sized;

    /// Signature Type
    type Signature;
}

/// Signature Verifying Key Derivation Function
pub trait Derive<COM = ()>: Types {
    /// Derives the verifying key from `signing_key` inside `compiler`.
    fn derive_with(&self, signing_key: &Self::SigningKey, compiler: &mut COM)
        -> Self::VerifyingKey;

    /// Derives the verifying key from `signing_key`.
    #[inline]
    fn derive(&self, signing_key: &Self::SigningKey) -> Self::VerifyingKey
    where
        COM: Native,
    {
        self.derive_with(signing_key, &mut COM::compiler())
    }
}

/// Signature Creation
pub trait Sign<COM = ()>: Types {
    /// Signs `message` with the `signing_key` using the randomly sampled `randomness` inside the
    /// `compiler`.
    fn sign_with(
        &self,
        randomness: &Self::Randomness,
        signing_key: &Self::SigningKey,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature;

    /// Signs `message` with the `signing_key` using the randomly sampled `randomness`.
    #[inline]
    fn sign(
        &self,
        randomness: &Self::Randomness,
        signing_key: &Self::SigningKey,
        message: &Self::Message,
    ) -> Self::Signature
    where
        COM: Native,
    {
        self.sign_with(randomness, signing_key, message, &mut COM::compiler())
    }
}

/// Signature Verification
pub trait Verify: Types {
    /// Verifies that the `signature` of `message` was signed with the signing key deriving
    /// `verifying_key`.
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
    ) -> bool;
}

/// Schnorr Signature
pub mod schnorr {
    use super::*;
    use crate::{
        algebra::{Field, Group},
        constraint::Native,
    };
    use core::marker::PhantomData;

    /// Schnorr Hash Function
    ///
    /// This hash function is used by [`Schnorr`] to implement the key-prefixed Schnorr signature
    /// protocol. See its documentation for more.
    pub trait HashFunction<G, COM = ()>
    where
        G: Group<COM>,
    {
        /// Message Type
        type Message;

        /// Hashes `random_point`, `verifying_key` and `message` into a [`Scalar`](Group::Scalar)
        /// inside of `compiler`.
        fn hash_with(
            &self,
            random_point: &G,
            verifying_key: &G,
            message: &Self::Message,
            compiler: &mut COM,
        ) -> G::Scalar;

        /// Hashes `random_point`, `verifying_key` and `message` into a [`Scalar`](Group::Scalar).
        #[inline]
        fn hash(&self, random_point: &G, verifying_key: &G, message: &Self::Message) -> G::Scalar
        where
            COM: Native,
        {
            self.hash_with(random_point, verifying_key, message, &mut COM::compiler())
        }
    }

    /// Schnorr Signature
    ///
    /// This `struct` implements the key-prefixed Schnorr signature protocol. See [`HashFunction`]
    /// for more.
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct Schnorr<G, H, COM = ()>
    where
        G: Group<COM>,
        H: HashFunction<G, COM>,
    {
        /// Group Generator
        pub generator: G,

        /// Hash Function
        pub hash_function: H,

        /// Type Parameter Marker
        __: PhantomData<COM>,
    }

    impl<G, H, COM> Schnorr<G, H, COM>
    where
        G: Group<COM>,
        H: HashFunction<G, COM>,
    {
        /// Builds a new [`Schnorr`] signature protocol over `generator` and `hash_function`.
        #[inline]
        pub fn new(generator: G, hash_function: H) -> Self {
            Self {
                generator,
                hash_function,
                __: PhantomData,
            }
        }
    }

    impl<G, H, COM> Types for Schnorr<G, H, COM>
    where
        G: Group<COM>,
        H: HashFunction<G, COM>,
    {
        type Randomness = G::Scalar;
        type SigningKey = G::Scalar;
        type VerifyingKey = G;
        type Message = H::Message;
        type Signature = (G::Scalar, G);
    }

    impl<G, H, COM> Derive<COM> for Schnorr<G, H, COM>
    where
        G: Group<COM>,
        H: HashFunction<G, COM>,
    {
        #[inline]
        fn derive_with(
            &self,
            signing_key: &Self::SigningKey,
            compiler: &mut COM,
        ) -> Self::VerifyingKey {
            self.generator.scalar_mul_with(signing_key, compiler)
        }
    }

    impl<G, H, COM> Sign<COM> for Schnorr<G, H, COM>
    where
        G: Group<COM>,
        H: HashFunction<G, COM>,
    {
        #[inline]
        fn sign_with(
            &self,
            randomness: &Self::Randomness,
            signing_key: &Self::SigningKey,
            message: &Self::Message,
            compiler: &mut COM,
        ) -> Self::Signature {
            let random_point = self.generator.scalar_mul_with(randomness, compiler);
            (
                randomness.add_with(
                    &self
                        .hash_function
                        .hash_with(
                            &random_point,
                            &self.generator.scalar_mul_with(signing_key, compiler),
                            message,
                            compiler,
                        )
                        .mul_with(signing_key, compiler),
                    compiler,
                ),
                random_point,
            )
        }
    }

    impl<G, H> Verify for Schnorr<G, H>
    where
        G: Group + PartialEq,
        H: HashFunction<G>,
    {
        #[inline]
        fn verify(
            &self,
            verifying_key: &Self::VerifyingKey,
            message: &Self::Message,
            signature: &Self::Signature,
        ) -> bool {
            self.generator.scalar_mul(&signature.0)
                == signature
                    .1
                    .add(&verifying_key.scalar_mul(&self.hash_function.hash(
                        &signature.1,
                        verifying_key,
                        message,
                    )))
        }
    }
}
