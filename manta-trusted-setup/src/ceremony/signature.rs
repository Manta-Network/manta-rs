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

use crate::ceremony::CeremonyError;

/// Public Key
pub trait HasPublicKey {
    /// Public Key Type
    type PublicKey;

    /// Returns the public key.
    fn public_key(&self) -> Self::PublicKey;
}

/// Signature Scheme
pub trait SignatureScheme {
    /// Public Key Type
    type PublicKey;

    /// Private Key Type
    type PrivateKey;

    /// Nounce Type
    type Nounce: ?Sized + 'static;

    /// Signature Type
    type Signature;
}

/// Signable Message
pub trait Sign<S>
where
    S: SignatureScheme,
{
    /// Signature Type
    type Signature;

    /// Sign the message
    fn sign(
        &self,
        nounce: &S::Nounce,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<Self::Signature, CeremonyError>;
}

/// Verify
pub trait Verify<S>
where
    S: SignatureScheme,
{
    /// Signature Type
    type Signature;

    /// Verifies the integrity of the `signature`.
    fn verify(
        &self,
        nounce: &S::Nounce,
        public_key: &S::PublicKey,
        signature: &Self::Signature,
    ) -> Result<(), CeremonyError>;
}

/// Signed message
pub struct Signed<T, S>
where
    T: Verify<S>,
    S: SignatureScheme,
{
    /// Message
    pub message: T,

    /// Signature
    pub signature: T::Signature,
}

impl<T, S> Signed<T, S>
where
    T: Verify<S>,
    S: SignatureScheme,
    T: Sized,
    <T as Verify<S>>::Signature: Sized,
{
    /// Verify integrity of the message
    pub fn verify(
        &self,
        nounce: &S::Nounce,
        public_key: &S::PublicKey,
    ) -> Result<(), CeremonyError> {
        self.message.verify(nounce, public_key, &self.signature)
    }
}

/// ED25519 Signature Scheme
pub mod ed_dalek {
    use super::*;
    use alloc::vec::Vec;
    use ed25519_dalek::{self, Signer, Verifier};
    use manta_util::{
        into_array_unchecked,
        serde::{Deserialize, Serialize},
        serde_with::serde_as,
    };

    /// The dalek implementation of `ed25519` signatures.
    pub struct Ed25519 {}

    /// The public key for signed messages from contributors. This is a wrapper around the
    /// byte representation of an `ed25519_dalek::PublicKey` type.  The original type does
    /// not implement `Hash` and so cannot be used as a key in the `Registry`.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct PublicKey(pub [u8; 32]);

    /// The private key for signed messages from contributors. This is a wrapper around the
    /// byte representation of an `ed25519_dalek::SecretKey` type. The byte representation
    /// is used to be consistent with the choice made for `ContributorPublicKey`.
    #[derive(Debug)]
    pub struct PrivateKey(pub [u8; 32]);

    /// The type for message signatures.
    #[serde_as]
    #[derive(Debug, Serialize, Deserialize, Copy, Clone)]
    pub struct Signature(
        #[serde_as(as = "[_; ed25519_dalek::Signature::BYTE_SIZE]")]
        [u8; ed25519_dalek::Signature::BYTE_SIZE],
    );

    impl From<ed25519_dalek::Signature> for Signature {
        fn from(f: ed25519_dalek::Signature) -> Self {
            Signature(f.to_bytes())
        }
    }

    impl From<Signature> for ed25519_dalek::Signature {
        fn from(f: Signature) -> Self {
            ed25519_dalek::Signature::from_bytes(&f.0).expect("Should never fail")
        }
    }

    impl SignatureScheme for Ed25519 {
        type PublicKey = PublicKey;
        type PrivateKey = PrivateKey;
        type Signature = Signature;
        type Nounce = [u8];
    }

    /// The signable messages
    pub struct Message<'a>(&'a [u8]);

    impl<'a> From<&'a [u8]> for Message<'a> {
        fn from(s: &'a [u8]) -> Self {
            Self(s)
        }
    }

    impl<'a> Sign<Ed25519> for Message<'a> {
        type Signature = Signature;

        fn sign(
            &self,
            nounce: &[u8],
            public_key: &<Ed25519 as SignatureScheme>::PublicKey,
            private_key: &<Ed25519 as SignatureScheme>::PrivateKey,
        ) -> Result<<Ed25519 as SignatureScheme>::Signature, CeremonyError> {
            // Read keypair from byte representation of pub/priv keys
            let keypair = ed25519_dalek::Keypair::from_bytes(
                &[&private_key.0[..], &public_key.0[..]].concat(),
            )
            .expect("Failed to decode keypair from bytes"); // todo: error handling

            let msg = nounce
                .iter()
                .chain(self.0.iter())
                .copied()
                .collect::<Vec<_>>();

            let sig = keypair.sign(&msg);
            Ok(Signature(into_array_unchecked(sig)))
        }
    }

    impl<'a> Verify<Ed25519> for Message<'a> {
        type Signature = Signature;

        fn verify(
            &self,
            nounce: &[u8],
            public_key: &<Ed25519 as SignatureScheme>::PublicKey,
            signature: &<Ed25519 as SignatureScheme>::Signature,
        ) -> Result<(), CeremonyError> {
            let pub_key = ed25519_dalek::PublicKey::from_bytes(&public_key.0[..]).unwrap(); // todo: error handling
            let msg = nounce
                .iter()
                .chain(self.0.iter())
                .copied()
                .collect::<Vec<_>>();
            pub_key
                .verify(&msg, &((*signature).into()))
                .map_err(|_| CeremonyError::InvalidSignature)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        /// These were originally generated by the `Keypair::generate` method.
        pub fn test_keypair() -> (PrivateKey, PublicKey) {
            (
                PrivateKey([
                    149, 167, 173, 208, 224, 206, 37, 70, 87, 169, 157, 198, 120, 32, 151, 88, 25,
                    10, 12, 215, 80, 124, 187, 129, 183, 96, 103, 11, 191, 255, 33, 105,
                ]),
                PublicKey([
                    104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2,
                    138, 148, 242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
                ]),
            )
        }

        #[test]
        fn signature_test() {
            let (priv_key, pub_key) = test_keypair();
            let message = Message(b"Test message");
            let signature =
                <Message as Sign<Ed25519>>::sign(&message, "".as_bytes(), &pub_key, &priv_key)
                    .unwrap();

            assert!(<Message as Verify<Ed25519>>::verify(
                &message,
                "".as_bytes(),
                &pub_key,
                &signature
            )
            .is_ok())
        }
    }
}
