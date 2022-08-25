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

//! Signature Scheme

use manta_crypto::signature::{self, RandomnessType};
use manta_util::serde::Serialize;

/// Nonce
pub trait Nonce: Clone + PartialEq {
    /// Increments the current nonce by one.
    fn increment(&self) -> Self;

    /// Checks if the current nonce is valid
    fn is_valid(&self) -> bool;
}

impl Nonce for u64 {
    #[inline]
    fn increment(&self) -> Self {
        self.saturating_add(1)
    }

    #[inline]
    fn is_valid(&self) -> bool {
        *self != Self::MAX
    }
}

/// Checks if two nonces `current`and `user_nonce` are both valid and equal to each other.
#[inline]
pub fn check_nonce<N>(current: &N, user_nonce: &N) -> bool
where
    N: Nonce,
{
    current.is_valid() && user_nonce.is_valid() && current == user_nonce
}

/// Signature Scheme
pub trait SignatureScheme<T>:
    signature::MessageType<Message = (Self::Nonce, T)> + signature::Sign + signature::Verify
{
    /// Message Nonce
    type Nonce: Nonce;

    /// Builds a new Signer.
    fn new() -> Self;

    /// Generates randomness.
    fn gen_randomness(&self) -> Self::Randomness;
}

/// Has Nonce
pub trait HasNonce<S, T>
where
    S: SignatureScheme<T>,
{
    /// Returns the nonce of `self` as a participant.
    fn nonce(&self) -> S::Nonce;

    /// Sets nonce.
    fn set_nonce(&mut self, nonce: S::Nonce);
}

/// Public Key
pub trait HasPublicKey<S, T>
where
    S: SignatureScheme<T>,
{
    /// Returns the public key.
    fn public_key(&self) -> S::VerifyingKey;
}

/// ED25519 Signature Scheme
pub mod ed_dalek {
    use super::*;
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
    use manta_crypto::{
        arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
        eclair::alloc::mode::Public,
        signature::{
            RandomnessType, Sign, SignatureType, SigningKeyType, Verify, VerifyingKey,
            VerifyingKeyType,
        },
    };
    use manta_util::{into_array_unchecked, serde::Deserialize, Array};
    use std::io::{Read, Write};

    /// ED25519-Dalek Signature
    pub struct Ed25519;

    impl signature::MessageType for Ed25519 {
        type Message = (u64, Vec<u8>);
    }

    impl RandomnessType for Ed25519 {
        // # Note
        // `ed25519_dalet` provides randomness so we set it as empty here.
        type Randomness = ();
    }

    impl SignatureType for Ed25519 {
        type Signature = Array<u8, 64>;
    }

    impl SigningKeyType for Ed25519 {
        type SigningKey = Array<u8, 32>;
    }

    impl VerifyingKeyType for Ed25519 {
        type VerifyingKey = Array<u8, 32>;
    }

    impl Sign for Ed25519 {
        fn sign(
            &self,
            signing_key: &Self::SigningKey,
            randomness: &Self::Randomness,
            message: &Self::Message,
            compiler: &mut (),
        ) -> Self::Signature {
            let _ = (randomness, compiler);
            let mut message_concatenated = Vec::new();
            CanonicalSerialize::serialize(&message.0, &mut message_concatenated)
                .expect("Serializing u64 should succeed.");
            message_concatenated.extend_from_slice(message.1.as_ref());
            let secret_key: SecretKey =
                SecretKey::from_bytes(&signing_key.0).expect("Should give secret key.");
            let public_key: PublicKey = (&secret_key).into();
            Array::from_unchecked(
                Keypair {
                    secret: secret_key,
                    public: public_key,
                }
                .sign(&message_concatenated),
            )
        }
    }

    impl Verify for Ed25519 {
        type Verification = Result<(), ()>;

        fn verify(
            &self,
            verifying_key: &Self::VerifyingKey,
            message: &Self::Message,
            signature: &Self::Signature,
            _: &mut (),
        ) -> Self::Verification {
            let mut message_concatenated = Vec::new();
            CanonicalSerialize::serialize(&message.0, &mut message_concatenated)
                .expect("Serializing u64 should succeed.");
            message_concatenated.extend_from_slice(message.1.as_ref());
            PublicKey::from_bytes(&verifying_key.0)
                .expect("Should decode public key from bytes.")
                .verify(
                    &message_concatenated,
                    &Signature::from_bytes(&signature.0).expect("Should never fail."),
                )
                .map_err(drop)
        }
    }

    impl SignatureScheme<Vec<u8>> for Ed25519 {
        type Nonce = u64;

        #[inline]
        fn new() -> Self {
            Ed25519
        }

        fn gen_randomness(&self) -> Self::Randomness {
            ()
        }
    }
}

/// Testing Suites
#[cfg(test)]
mod test {
    use super::ed_dalek::*;
    use manta_crypto::signature::{Sign, Verify};
    use manta_util::Array;

    /// Tests if sign and verify a message is correct.
    #[test]
    fn sign_and_verify_is_correct() {
        let signing_key = Array::<u8, 32>::from_unchecked([
            149, 167, 173, 208, 224, 206, 37, 70, 87, 169, 157, 198, 120, 32, 151, 88, 25, 10, 12,
            215, 80, 124, 187, 129, 183, 96, 103, 11, 191, 255, 33, 105,
        ]);
        let verifying_key = Array::<u8, 32>::from_unchecked([
            104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2, 138, 148,
            242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
        ]);
        let message = b"Test message";
        let nonce = 1;
        let signer = Ed25519;
        let signature = signer.sign(&signing_key, &(), &(nonce, message.to_vec()), &mut ());
        signer
            .verify(
                &verifying_key,
                &(nonce, message.to_vec()),
                &signature,
                &mut (),
            )
            .expect("Should verify the signature.");
    }
}
