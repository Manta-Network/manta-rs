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

use manta_crypto::signature;
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
    signature::Sign<Randomness = (), Message = (Self::Nonce, T)>
    + signature::Verify<Verification = Result<(), Self::Error>>
{
    /// Error
    type Error;

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
    use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
    use manta_crypto::signature::{
        RandomnessType, Sign, SignatureType, SigningKeyType, Verify, VerifyingKeyType,
    };
    use manta_util::Array;

    /// ED25519-Dalek Signature
    #[derive(Clone)]
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
        #[inline]
        fn sign(
            &self,
            signing_key: &Self::SigningKey,
            randomness: &Self::Randomness,
            message: &Self::Message,
            compiler: &mut (),
        ) -> Self::Signature {
            let _ = (randomness, compiler);
            let mut writer = Vec::new();
            serde_json::to_writer(&mut writer, &message.0)
                .expect("Serializing nonce should succeed.");
            writer.extend_from_slice(message.1.as_ref());
            let (secret, public) = Self::to_dalek_key(signing_key);
            Array::from_unchecked(Keypair { secret, public }.sign(&writer))
        }
    }

    impl Verify for Ed25519 {
        type Verification = Result<(), ()>;

        #[inline]
        fn verify(
            &self,
            verifying_key: &Self::VerifyingKey,
            message: &Self::Message,
            signature: &Self::Signature,
            _: &mut (),
        ) -> Self::Verification {
            let mut writer = Vec::new();
            serde_json::to_writer(&mut writer, &message.0)
                .expect("Serializing nonce should succeed.");
            writer.extend_from_slice(message.1.as_ref());
            PublicKey::from_bytes(&verifying_key.0)
                .expect("Should decode public key from bytes.")
                .verify(
                    &writer,
                    &Signature::from_bytes(&signature.0).expect("Should never fail."),
                )
                .map_err(drop)
        }
    }

    impl SignatureScheme<Vec<u8>> for Ed25519 {
        type Error = ();

        type Nonce = u64;

        #[inline]
        fn new() -> Self {
            Ed25519
        }

        #[inline]
        fn gen_randomness(&self) -> Self::Randomness {
            ()
        }
    }

    impl Ed25519 {
        /// Generates Ed25519 key pair.
        #[inline]
        pub fn generate_keys(
            seed_bytes: &[u8],
        ) -> (
            <Self as SigningKeyType>::SigningKey,
            <Self as VerifyingKeyType>::VerifyingKey,
        ) {
            assert!(ed25519_dalek::SECRET_KEY_LENGTH <= seed_bytes.len(), "Secret key length of ed25519 should be smaller than length of seed bytes from mnemonic phrases.");
            let sk = ed25519_dalek::SecretKey::from_bytes(
                &seed_bytes[0..ed25519_dalek::SECRET_KEY_LENGTH],
            )
            .expect("`from_bytes` should succeed for SecretKey.");
            let pk: ed25519_dalek::PublicKey = (&sk).into();
            Self::from_dalek_key(sk, pk)
        }

        /// Converts Ed25519 signing key to `ed25519_dalek` key pair.
        #[inline]
        pub fn to_dalek_key(
            signing_key: &<Self as SigningKeyType>::SigningKey,
        ) -> (ed25519_dalek::SecretKey, ed25519_dalek::PublicKey) {
            let sk = ed25519_dalek::SecretKey::from_bytes(&signing_key.0)
                .expect("`from_bytes` should succeed for SecretKey.");
            let pk: ed25519_dalek::PublicKey = (&sk).into();
            (sk, pk)
        }

        /// Converts `ed25519_dalek` key pair to Ed25519 key pair.
        #[inline]
        pub fn from_dalek_key(
            secret_key: ed25519_dalek::SecretKey,
            public_key: ed25519_dalek::PublicKey,
        ) -> (
            <Self as SigningKeyType>::SigningKey,
            <Self as VerifyingKeyType>::VerifyingKey,
        ) {
            (
                Array::from_unchecked(secret_key.to_bytes()),
                Array::from_unchecked(public_key.to_bytes()),
            )
        }
    }
}

/// Signs a `(nonce, message)` with `signing_key`.
#[inline]
pub fn sign<T, S>(message: &T, nonce: S::Nonce, signing_key: &S::SigningKey) -> S::Signature
where
    T: Serialize,
    S: SignatureScheme<Vec<u8>>,
{
    let signer = S::new();
    let mut writer = Vec::new();
    serde_json::to_writer(&mut writer, &message).expect("Serialization should succeed.");
    signer.sign(signing_key, &(), &(nonce, writer), &mut ())
}

/// Verifies the signature of `(nonce, message)` with `verifying_key`.
#[inline]
pub fn verify<T, S>(
    message: &T,
    nonce: S::Nonce,
    verifying_key: &S::VerifyingKey,
    signature: &S::Signature,
) -> Result<(), S::Error>
where
    T: Serialize,
    S: SignatureScheme<Vec<u8>>,
{
    let signer = S::new();
    let mut writer = Vec::new();
    serde_json::to_writer(&mut writer, &message).expect("Serialization should succeed.");
    signer.verify(verifying_key, &(nonce, writer), signature, &mut ())
}

/// Testing Suites
#[cfg(test)]
mod test {
    use super::{ed_dalek::*, *};
    use bip39::{Language, Mnemonic, MnemonicType, Seed};
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

    /// Key conversion is correct.
    #[test]
    fn key_conversion_is_correct() {
        let seed_bytes = [
            149, 167, 173, 208, 224, 206, 37, 70, 87, 169, 157, 198, 120, 32, 151, 88, 25, 10, 12,
            215, 80, 124, 187, 129, 183, 96, 103, 11, 191, 255, 33, 105,
        ];
        let expected_signing_key = Array::<u8, 32>::from_unchecked(seed_bytes);
        let expected_verifying_key = Array::<u8, 32>::from_unchecked([
            104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2, 138, 148,
            242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
        ]);
        let ed25519_key_pair = Ed25519::generate_keys(&seed_bytes);
        assert_eq!(ed25519_key_pair.0, expected_signing_key);
        assert_eq!(ed25519_key_pair.1, expected_verifying_key);
        let dalek_key_pair = Ed25519::to_dalek_key(&expected_signing_key);
        assert_eq!(
            Ed25519::from_dalek_key(dalek_key_pair.0, dalek_key_pair.1),
            (expected_signing_key, expected_verifying_key)
        );
    }

    /// Tests if sign and verify are compatible with serialization.
    #[test]
    fn signature_and_serialization_is_compatible() {
        let twitter_account = "mantalorian";
        let email = "mantalorian@manta.network";
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, "manta-trusted-setup");
        let (sk, pk) = Ed25519::generate_keys(seed.as_bytes());
        let pk_string = bs58::encode(pk).into_string();
        let signer = Ed25519;
        let signature = signer.sign(
            &sk,
            &signer.gen_randomness(),
            &(
                0,
                format!(
                    "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                    twitter_account, email
                )
                .as_bytes()
                .into(),
            ),
            &mut (),
        );
        let signature_string = bs58::encode(signature).into_string();
        let public_key: Array<u8, 32> =
            Array::from_unchecked(bs58::decode(pk_string).into_vec().unwrap());
        let signature: Array<u8, 64> =
            Array::from_unchecked(bs58::decode(signature_string).into_vec().unwrap());
        signer
            .verify(
                &public_key,
                &(
                    0,
                    format!(
                        "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                        twitter_account, email
                    )
                    .as_bytes()
                    .into(),
                ),
                &signature,
                &mut (),
            )
            .expect("Verifying signature should succeed.");
    }
}
