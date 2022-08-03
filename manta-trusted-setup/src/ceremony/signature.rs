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
    type Nounce;

    /// Signature Type
    type Signature;
}

/// Signable Message
pub trait Sign<S>
where
    S: SignatureScheme,
{
    /// Sign the message
    fn sign(
        &self,
        nounce: &S::Nounce,
        public_key: &S::PublicKey, // TODO: Signature does not need public key.
        private_key: &S::PrivateKey,
    ) -> Result<S::Signature, CeremonyError>;
}

/// Verify
pub trait Verify<S>
where
    S: SignatureScheme,
{
    /// Verifies the integrity of the `signature`.
    fn verify(
        &self,
        nounce: &S::Nounce,
        public_key: &S::PublicKey,
        signature: &S::Signature,
    ) -> Result<(), CeremonyError>;
}

/// Signed Message
pub struct SignedMessage<T, S>
where
    S: SignatureScheme,
    T: Verify<S>,
{
    /// Message
    pub message: T,

    /// Signature
    pub signature: S::Signature,
}

impl<T, S> SignedMessage<T, S>
where
    S: SignatureScheme,
    T: Verify<S>,
{
    /// Verifies the integrity of the message
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
    use core::iter;
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
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
    pub struct PublicKey(pub [u8; 32]);

    /// Private Key Type
    ///
    /// # Note
    ///
    /// A wrapper around the byte representation of an `ed25519_dalek::SecretKey` type. The byte
    /// representation is used to be consistent with the choice made for `PublicKey`.
    #[derive(Debug)]
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

    impl SignatureScheme for Ed25519 {
        type PublicKey = PublicKey;
        type PrivateKey = PrivateKey;
        type Signature = Signature;
        type Nounce = u8;
    }

    /// The signable messages
    pub struct Message<'a>(pub &'a [u8]);

    impl<'a> From<&'a [u8]> for Message<'a> {
        fn from(s: &'a [u8]) -> Self {
            Self(s)
        }
    }

    impl<'a> Sign<Ed25519> for Message<'a> {
        fn sign(
            &self,
            nounce: &<Ed25519 as SignatureScheme>::Nounce,
            public_key: &<Ed25519 as SignatureScheme>::PublicKey,
            private_key: &<Ed25519 as SignatureScheme>::PrivateKey,
        ) -> Result<<Ed25519 as SignatureScheme>::Signature, CeremonyError> {
            Ok(Signature(into_array_unchecked(
                Keypair::from_bytes(&[&private_key.0[..], &public_key.0[..]].concat())
                    .expect("Should decode keypair from bytes.")
                    .sign(
                        &iter::once(nounce)
                            .chain(self.0.iter())
                            .copied()
                            .collect::<Vec<_>>(),
                    ),
            )))
        }
    }

    impl<'a> Verify<Ed25519> for Message<'a> {
        fn verify(
            &self,
            nounce: &<Ed25519 as SignatureScheme>::Nounce,
            public_key: &<Ed25519 as SignatureScheme>::PublicKey,
            signature: &<Ed25519 as SignatureScheme>::Signature,
        ) -> Result<(), CeremonyError> {
            ed25519_dalek::PublicKey::from_bytes(&public_key.0[..])
                .expect("Should decode public key from bytes.")
                .verify(
                    &iter::once(nounce)
                        .chain(self.0.iter())
                        .copied()
                        .collect::<Vec<_>>(),
                    &((*signature).into()),
                )
                .map_err(|_| CeremonyError::InvalidSignature)
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
        let message = Message(b"Test message");
        let nounce = 1;
        assert!(
            message
                .verify(
                    &nounce,
                    &public_key,
                    &message
                        .sign(&nounce, &public_key, &private_key)
                        .expect("Should generate a signature.")
                )
                .is_ok(),
            "Should verify the signature."
        );
    }
}
