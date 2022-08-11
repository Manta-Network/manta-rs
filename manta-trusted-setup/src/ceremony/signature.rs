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

use manta_util::serde::Serialize;

/// Public Key
pub trait HasPublicKey<S>
where
    S: SignatureScheme,
{
    /// Returns the public key.
    fn public_key(&self) -> S::PublicKey;
}

/// Nonce
pub trait Nonce: Serialize + PartialEq + Clone {
    /// Increment the current nonce by one.
    fn increment(&mut self);
}

/// Signature Scheme
pub trait SignatureScheme {
    /// Public Key Type
    type PublicKey;

    /// Private Key Type
    type PrivateKey;

    /// Nonce Type
    type Nonce: Nonce;

    /// Signature Type
    type Signature;

    /// Signs a `message` and `nonce` with `(public_key, private_key)`.
    fn sign_bytes<M>(
        message: &M,
        nonce: &Self::Nonce,
        public_key: &Self::PublicKey,
        private_key: &Self::PrivateKey,
    ) -> Result<Self::Signature, ()> // TODO: Change to ceremony error
    where
        M: ?Sized + AsRef<[u8]>;

    /// Signs a `message` and `nonce` with `(public_key, private_key)`.
    fn sign<M>(
        message: M,
        nonce: &Self::Nonce,
        public_key: &Self::PublicKey,
        private_key: &Self::PrivateKey,
    ) -> Result<Self::Signature, ()> // TODO: Change to ceremony error
    where
        M: Serialize,
    {
        Self::sign_bytes(
            &bincode::serialize(&message).expect("Should serialize message."),
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
    ) -> Result<(), ()> // TODO: Change to ceremony error
    where
        M: ?Sized + AsRef<[u8]>;

    /// Verifies the `signature` of `message` and `nonce` with `public_key`.
    fn verify<M>(
        message: M,
        nonce: &Self::Nonce,
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<(), ()> // TODO: Change to ceremony error
    where
        M: Serialize,
    {
        Self::verify_bytes(
            &bincode::serialize(&message).expect("Should serialize message."),
            nonce,
            signature,
            public_key,
        )
    }
}

/// ED25519 Signature Scheme
pub mod ed_dalek {
    use super::*;
    use ed25519_dalek::{Keypair, Signature as ED25519Signature, Signer, Verifier};
    use manta_util::{
        into_array_unchecked,
        serde::{Deserialize, Serialize},
        serde_with::serde_as,
    };

    /// ED25519-Dalek Signature
    pub struct Ed25519;

    /// Public Key Type
    ///
    /// # Note
    ///
    /// A wrapper around the byte representation of an `ed25519_dalek::PublicKey` type. The original
    /// type does not implement `Hash` and so cannot be used as a key in the `Registry`.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
    pub struct PublicKey(pub [u8; 32]);

    /// Private Key Type
    ///
    /// # Note
    ///
    /// A wrapper around the byte representation of an `ed25519_dalek::SecretKey` type. The byte
    /// representation is used to be consistent with the choice made for `PublicKey`.
    #[derive(Debug, Serialize, Deserialize, Clone, Copy)]
    pub struct PrivateKey(pub [u8; 32]);

    /// Signature Type
    #[serde_as] // TODO: May use other serialize methods
    #[derive(Debug, Serialize, Deserialize, Copy, Clone)]
    pub struct Signature(
        #[serde_as(as = "[_; ed25519_dalek::Signature::BYTE_SIZE]")]
        [u8; ED25519Signature::BYTE_SIZE],
    );

    impl From<ED25519Signature> for Signature {
        fn from(f: ED25519Signature) -> Self {
            Signature(f.to_bytes())
        }
    }

    impl From<Signature> for ED25519Signature {
        fn from(f: Signature) -> Self {
            ED25519Signature::from_bytes(&f.0).expect("Should never fail.")
        }
    }

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
            let mut message_concatenated =
                bincode::serialize(nonce).expect("Serializing nonce should not fail");
            message_concatenated.extend_from_slice(message.as_ref());
            Ok(Signature(into_array_unchecked(
                Keypair::from_bytes(&[&private_key.0[..], &public_key.0[..]].concat())
                    .expect("Should decode keypair from bytes.")
                    .sign(&message_concatenated),
            )))
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
            let mut message_concatenated =
                bincode::serialize(nonce).expect("Serializing nonce should not fail.");
            message_concatenated.extend_from_slice(message.as_ref());
            let verify_result = ed25519_dalek::PublicKey::from_bytes(&public_key.0[..])
                .expect("Should decode public key from bytes.")
                .verify(&message_concatenated, &((*signature).into()));
            verify_result.map_err(drop)
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
        let private_key = PrivateKey([
            149, 167, 173, 208, 224, 206, 37, 70, 87, 169, 157, 198, 120, 32, 151, 88, 25, 10, 12,
            215, 80, 124, 187, 129, 183, 96, 103, 11, 191, 255, 33, 105,
        ]);
        let public_key = PublicKey([
            104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2, 138, 148,
            242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
        ]);
        let message = b"Test message";
        let nounce = 1;
        let signature = Ed25519::sign_bytes(message, &nounce, &public_key, &private_key)
            .expect("Should sign the message.");
        Ed25519::verify_bytes(message, &nounce, &signature, &public_key)
            .expect("Should verify the signature.");
    }
}
