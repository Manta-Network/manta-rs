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

use serde::Serialize;

/// Public Key
pub trait HasPublicKey<S>
where
    S: SignatureScheme,
{
    /// Returns the public key.
    fn public_key(&self) -> S::PublicKey;
}

/// Nonce
pub trait Nonce: PartialEq + Clone {
    /// Increment the current nonce by one.
    fn increment(&mut self);
}

/// Has Nonce
pub trait HasNonce<S>
where
    S: SignatureScheme,
{
    /// Returns the nonce of `self` as a participant.
    fn nonce(&self) -> S::Nonce;

    /// Sets nonce.
    fn set_nonce(&mut self, nonce: S::Nonce);
}

/// Signature Scheme
pub trait SignatureScheme {
    /// Public Key Type
    type PublicKey;

    /// Private Key Type
    type PrivateKey;

    /// Nonce Type
    type Nonce: Nonce + Serialize;

    /// Signature Type
    type Signature;

    /// Signs a `message` and `nonce` with `(public_key, private_key)`.
    fn sign_bytes<M>(
        message: &M,
        nonce: &Self::Nonce,
        public_key: &Self::PublicKey,
        private_key: &Self::PrivateKey,
    ) -> Result<Self::Signature, ()>
    // TODO: Change to ceremony error
    where
        M: ?Sized + AsRef<[u8]>;

    /// Signs a `message` and `nonce` with `(public_key, private_key)`.
    fn sign<M>(
        message: M,
        nonce: &Self::Nonce,
        public_key: &Self::PublicKey,
        private_key: &Self::PrivateKey,
    ) -> Result<Self::Signature, ()>
    // TODO: Change to ceremony error
    where
        M: Serialize,
    {
        Self::sign_bytes(
            &serde_json::to_string(&message)
                .expect("Serializing message should succeed.")
                .as_bytes(),
            nonce,
            public_key,
            private_key,
        )
    }

    /// Verifies the `signature` of `message` and `nonce` with `public_key`.
    fn verify_bytes<M>(
        message: &M,
        nonce: &Self::Nonce,
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<(), ()>
    // TODO: Change to ceremony error
    where
        M: ?Sized + AsRef<[u8]>;

    /// Verifies the `signature` of `message` and `nonce` with `public_key`.
    fn verify<M>(
        message: M,
        nonce: &Self::Nonce,
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<(), ()>
    // TODO: Change to ceremony error
    where
        M: Serialize,
    {
        Self::verify_bytes(
            &serde_json::to_string(&message)
                .expect("Serializing message should succeed.")
                .as_bytes(),
            nonce,
            signature,
            public_key,
        )
    }
}

/// ED25519 Signature Scheme
pub mod ed_dalek {
    use super::*;
    use crate::ceremony::state::U8Array;
    use ed25519_dalek::{Keypair, Signature as ED25519Signature, Signer, Verifier};
    use manta_crypto::arkworks::serialize::{
        CanonicalDeserialize, CanonicalSerialize, SerializationError,
    };
    use manta_util::into_array_unchecked;
    use serde::Deserialize;
    use std::io::{Read, Write};

    /// ED25519-Dalek Signature
    pub struct Ed25519;

    /// Public Key Type
    ///
    /// # Note
    ///
    /// A wrapper around the byte representation of an `ed25519_dalek::PublicKey` type. The original
    /// type does not implement `Hash` and so cannot be used as a key in the `Registry`.
    #[derive(
        Clone,
        Copy,
        Debug,
        Eq,
        Hash,
        PartialEq,
        Ord,
        PartialOrd,
        CanonicalDeserialize,
        CanonicalSerialize,
        Serialize,
        Deserialize,
    )]
    pub struct PublicKey(pub U8Array<32>);

    impl PublicKey {
        /// Returns raw bytes.
        #[inline]
        pub fn raw_bytes(&self) -> [u8; 32] {
            self.0 .0
        }
    }

    /// Private Key Type
    ///
    /// # Note
    ///
    /// A wrapper around the byte representation of an `ed25519_dalek::SecretKey` type. The byte
    /// representation is used to be consistent with the choice made for `PublicKey`.
    #[derive(Debug, Clone, Copy, CanonicalDeserialize, CanonicalSerialize)]
    pub struct PrivateKey(pub U8Array<32>);

    impl PrivateKey {
        /// Returns raw bytes.
        #[inline]
        pub fn raw_bytes(&self) -> [u8; 32] {
            self.0 .0
        }
    }

    /// Signature Type
    #[derive(
        Debug, Copy, Clone, CanonicalDeserialize, CanonicalSerialize, Serialize, Deserialize,
    )]
    pub struct Signature(U8Array<64>);

    impl Signature {
        /// Returns raw bytes.
        #[inline]
        pub fn raw_bytes(&self) -> [u8; 64] {
            self.0 .0
        }
    }

    impl From<ED25519Signature> for Signature {
        fn from(f: ED25519Signature) -> Self {
            Signature(f.to_bytes().into())
        }
    }

    impl From<Signature> for ED25519Signature {
        fn from(f: Signature) -> Self {
            ED25519Signature::from_bytes(&f.0 .0).expect("Should never fail.")
        }
    }

    // impl Serialize for Signature {
    //     #[inline]
    //     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    //     where
    //         S: serde::Serializer,
    //     {
    //         let mut s = serializer.serialize_struct("Signature", 1)?;
    //         s.serialize_field("U8Array", &self.0)?;
    //         s.end()
    //     }
    // }

    // impl Serialize for U8Array<32> {
    //     #[inline]
    //     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    //     where
    //         S: serde::Serializer,
    //     {
    //         let mut s = serializer.serialize_struct("U8Array", 1)?;
    //         s.serialize_field("first_half", &self.0[0..32])?;
    //         s.serialize_field("second_half", &self.0[32..64])?;
    //         s.end()
    //     }
    // }

    // impl<'de> Deserialize<'de> for U8Array<32> {
    //     #[inline]
    //     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    //     where
    //         D: serde::Deserializer<'de>,
    //     {
    //         todo!()
    //     }
    // }

    // impl Serialize for U8Array<64> {
    //     #[inline]
    //     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    //     where
    //         S: serde::Serializer,
    //     {
    //         let mut s = serializer.serialize_struct("U8Array", 1)?;
    //         s.serialize_field("first_half", &self.0[0..32])?;
    //         s.serialize_field("second_half", &self.0[32..64])?;
    //         s.end()
    //     }
    // }

    impl Nonce for u64 {
        fn increment(&mut self) {
            *self = self.wrapping_add(1);
        }
    }

    impl SignatureScheme for Ed25519 {
        type PublicKey = PublicKey;
        type PrivateKey = PrivateKey;
        type Nonce = u64;
        type Signature = Signature;

        fn sign_bytes<M>(
            message: &M,
            nonce: &Self::Nonce,
            public_key: &Self::PublicKey,
            private_key: &Self::PrivateKey,
        ) -> Result<Self::Signature, ()>
        where
            M: ?Sized + AsRef<[u8]>,
        {
            let mut message_concatenated = Vec::new();
            CanonicalSerialize::serialize(nonce, &mut message_concatenated)
                .expect("Serializing u64 should succeed.");
            message_concatenated.extend_from_slice(message.as_ref());
            Ok(Signature(
                into_array_unchecked(
                    Keypair::from_bytes(
                        &[private_key.raw_bytes(), public_key.raw_bytes()].concat(),
                    )
                    .expect("Should decode keypair from bytes.")
                    .sign(&message_concatenated),
                )
                .into(),
            ))
        }

        fn verify_bytes<M>(
            message: &M,
            nonce: &Self::Nonce,
            signature: &Self::Signature,
            public_key: &Self::PublicKey,
        ) -> Result<(), ()>
        where
            M: ?Sized + AsRef<[u8]>,
        {
            let mut message_concatenated = Vec::new();
            CanonicalSerialize::serialize(nonce, &mut message_concatenated)
                .expect("Serializing u64 should succeed.");
            message_concatenated.extend_from_slice(message.as_ref());
            ed25519_dalek::PublicKey::from_bytes(&public_key.raw_bytes())
                .expect("Should decode public key from bytes.")
                .verify(&message_concatenated, &((*signature).into()))
                .map_err(drop)
        }
    }
}

/// Testing Suites
#[cfg(test)]
mod test {
    use super::{ed_dalek::*, *};

    /// Tests if sign and verify a message is correct.
    #[test]
    fn sign_and_verify_is_correct() {
        let private_key = PrivateKey(
            [
                149, 167, 173, 208, 224, 206, 37, 70, 87, 169, 157, 198, 120, 32, 151, 88, 25, 10,
                12, 215, 80, 124, 187, 129, 183, 96, 103, 11, 191, 255, 33, 105,
            ]
            .into(),
        );
        let public_key = PublicKey(
            [
                104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2, 138,
                148, 242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
            ]
            .into(),
        );
        let message = b"Test message";
        let nounce = 1;
        let signature = Ed25519::sign_bytes(message, &nounce, &public_key, &private_key)
            .expect("Should sign the message.");
        Ed25519::verify_bytes(message, &nounce, &signature, &public_key)
            .expect("Should verify the signature.");
    }
}
