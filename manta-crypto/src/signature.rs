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
//!
//! A signature scheme is made up of these three `trait`s:
//!
//! - [`Derive`]
//! - [`Sign`]
//! - [`Verify`]
//!
//! with the following completeness property:
//!
//! For all possible inputs, the following function returns `true`:
//!
//! ```text
//! fn is_valid(signing_key: SigningKey, randomness: Randomness, message: Message) -> bool {
//!     verify(derive(signing_key), message, sign(randomness, signing_key, message))
//! }
//! ```
//!
//! See the [`correctness`](test::correctness) test for more.

/// Signing Key
pub trait SigningKeyType {
    /// Signing Key Type
    type SigningKey;
}

impl<T> SigningKeyType for &T
where
    T: SigningKeyType,
{
    type SigningKey = T::SigningKey;
}

/// Verifying Key
pub trait VerifyingKeyType {
    /// Verifying Key Type
    type VerifyingKey;
}

impl<T> VerifyingKeyType for &T
where
    T: VerifyingKeyType,
{
    type VerifyingKey = T::VerifyingKey;
}

/// Message
pub trait MessageType {
    /// Message Type
    type Message;
}

impl<T> MessageType for &T
where
    T: MessageType,
{
    type Message = T::Message;
}

/// Signature
pub trait SignatureType {
    /// Signature Type
    type Signature;
}

impl<T> SignatureType for &T
where
    T: SignatureType,
{
    type Signature = T::Signature;
}

/// Randomness
pub trait RandomnessType {
    /// Randomness Type
    type Randomness;
}

impl<T> RandomnessType for &T
where
    T: RandomnessType,
{
    type Randomness = T::Randomness;
}

/// Signature Verifying Key Derivation Function
pub trait Derive<COM = ()>: SigningKeyType + VerifyingKeyType {
    /// Derives the verifying key from `signing_key`.
    ///
    /// This function is used by the signer to generate their [`VerifyingKey`] that is sent to the
    /// verifier to check that the signature was valid.
    ///
    /// [`VerifyingKey`]: VerifyingKeyType::VerifyingKey
    fn derive(&self, signing_key: &Self::SigningKey, compiler: &mut COM) -> Self::VerifyingKey;
}

impl<D, COM> Derive<COM> for &D
where
    D: Derive<COM>,
{
    #[inline]
    fn derive(&self, signing_key: &Self::SigningKey, compiler: &mut COM) -> Self::VerifyingKey {
        (*self).derive(signing_key, compiler)
    }
}

/// Signature Creation
pub trait Sign<COM = ()>: MessageType + RandomnessType + SignatureType + SigningKeyType {
    /// Signs `message` with the `signing_key` using `randomness` to hide the signature.
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature;
}

impl<S, COM> Sign<COM> for &S
where
    S: Sign<COM>,
{
    #[inline]
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature {
        (*self).sign(signing_key, randomness, message, compiler)
    }
}

/// Signature Verification
pub trait Verify<COM = ()>: MessageType + SignatureType + VerifyingKeyType {
    /// Verification Result Type
    ///
    /// This type is typically either [`bool`], a [`Result`] type, or a compiler variable
    /// representing either of those concrete types.
    type Verification;

    /// Verifies that the `signature` of `message` was signed with the signing key deriving
    /// `verifying_key`.
    ///
    /// For correctness of the signature, `verifying_key` should have come from a call to
    /// [`Derive::derive`], performed by the signer.
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> Self::Verification;
}

impl<V, COM> Verify<COM> for &V
where
    V: Verify<COM>,
{
    type Verification = V::Verification;

    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> Self::Verification {
        (*self).verify(verifying_key, message, signature, compiler)
    }
}

/// Schnorr Signatures
pub mod schnorr {
    use super::*;
    use crate::{
        algebra::{security::DiscreteLogarithmHardness, Group, Scalar},
        eclair::{bool::Bool, cmp::PartialEq, Has},
        hash::security::PreimageResistance,
    };
    use core::{cmp, fmt::Debug, hash::Hash, marker::PhantomData};

    /// Schnorr Signature Hash Function
    pub trait HashFunction<G, COM = ()>: PreimageResistance
    where
        G: DiscreteLogarithmHardness + Group<COM>,
    {
        /// Message Type
        type Message;

        /// Hashes `message` along with `verifying_key` and `nonce_point` into a
        /// [`Scalar`](Group::Scalar).
        fn hash(
            &self,
            verifying_key: &G,
            nonce_point: &G,
            message: &Self::Message,
            compiler: &mut COM,
        ) -> G::Scalar;
    }

    /// Schnorr Signature
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = "G::Scalar: Clone, G: Clone"),
        Copy(bound = "G::Scalar: Copy, G: Copy"),
        Debug(bound = "G::Scalar: Debug, G: Debug"),
        Eq(bound = "G::Scalar: Eq, G: Eq"),
        Hash(bound = "G::Scalar: Hash, G: Hash"),
        PartialEq(bound = "G::Scalar: cmp::PartialEq, G: cmp::PartialEq")
    )]
    pub struct Signature<G, COM = ()>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
    {
        /// Scalar
        ///
        /// This scalar is the hash output multiplied by the secret key, blinded by the nonce
        /// factor.
        pub scalar: G::Scalar,

        /// Nonce Point
        ///
        /// This point is the generator of the Schnorr group multiplied by the secret nonce.
        pub nonce_point: G,
    }

    /// Schnorr Signature Scheme
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = "G: Clone, H: Clone"),
        Copy(bound = "G: Copy, H: Copy"),
        Debug(bound = "G: Debug, H: Debug"),
        Eq(bound = "G: Eq, H: Eq"),
        Hash(bound = "G: Hash, H: Hash"),
        PartialEq(bound = "G: cmp::PartialEq, H: cmp::PartialEq")
    )]
    pub struct Schnorr<G, H, COM = ()>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        /// Schnorr Group Generator
        pub generator: G,

        /// Schnorr Hash Function
        pub hash_function: H,

        /// Type Parameter Marker
        __: PhantomData<COM>,
    }

    impl<G, H, COM> SigningKeyType for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        type SigningKey = G::Scalar;
    }

    impl<G, H, COM> VerifyingKeyType for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        type VerifyingKey = G;
    }

    impl<G, H, COM> MessageType for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        type Message = H::Message;
    }

    impl<G, H, COM> SignatureType for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        type Signature = Signature<G, COM>;
    }

    impl<G, H, COM> RandomnessType for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        type Randomness = G::Scalar;
    }

    impl<G, H, COM> Derive<COM> for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        #[inline]
        fn derive(&self, signing_key: &Self::SigningKey, compiler: &mut COM) -> Self::VerifyingKey {
            self.generator.mul(signing_key, compiler)
        }
    }

    impl<G, H, COM> Sign<COM> for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM>,
        H: HashFunction<G, COM>,
    {
        #[inline]
        fn sign(
            &self,
            randomness: &Self::Randomness,
            signing_key: &Self::SigningKey,
            message: &Self::Message,
            compiler: &mut COM,
        ) -> Self::Signature {
            let nonce_point = self.generator.mul(randomness, compiler);
            Signature {
                scalar: randomness.add(
                    &signing_key.mul(
                        &self.hash_function.hash(
                            &self.generator.mul(signing_key, compiler),
                            &nonce_point,
                            message,
                            compiler,
                        ),
                        compiler,
                    ),
                    compiler,
                ),
                nonce_point,
            }
        }
    }

    impl<G, H, COM> Verify<COM> for Schnorr<G, H, COM>
    where
        G: DiscreteLogarithmHardness + Group<COM> + PartialEq<G, COM>,
        H: HashFunction<G, COM>,
        COM: Has<bool>,
    {
        type Verification = Bool<COM>;

        #[inline]
        fn verify(
            &self,
            verifying_key: &Self::VerifyingKey,
            message: &Self::Message,
            signature: &Self::Signature,
            compiler: &mut COM,
        ) -> Self::Verification {
            let Signature {
                scalar,
                nonce_point,
            } = signature;
            self.generator.mul(scalar, compiler).eq(
                &nonce_point.add(
                    &verifying_key.mul(
                        &self
                            .hash_function
                            .hash(verifying_key, nonce_point, message, compiler),
                        compiler,
                    ),
                    compiler,
                ),
                compiler,
            )
        }
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;

    /// Verifies that `scheme` produces self-consistent results on the given `signing_key`,
    /// `randomness`, and `message`.
    #[inline]
    pub fn correctness<S, COM>(
        scheme: &S,
        signing_key: &S::SigningKey,
        randomness: &S::Randomness,
        message: &S::Message,
        compiler: &mut COM,
    ) -> S::Verification
    where
        S: Derive<COM> + Sign<COM> + Verify<COM>,
    {
        scheme.verify(
            &scheme.derive(signing_key, compiler),
            message,
            &scheme.sign(signing_key, randomness, message, compiler),
            compiler,
        )
    }
}
