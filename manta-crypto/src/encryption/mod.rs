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

//! Encryption Primitives

// TODO: pub mod authenticated;
// TODO: pub mod hybrid;
// TODO: pub mod symmetric;

/// Types
pub trait Types {
    /// Encryption Key Type
    type Key;

    /// Nonce Type
    type Nonce;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;
}

///
pub type Key<E> = <E as Types>::Key;

///
pub type Nonce<E> = <E as Types>::Nonce;

///
pub type Plaintext<E> = <E as Types>::Plaintext;

///
pub type Ciphertext<E> = <E as Types>::Ciphertext;

/// Encryption
pub trait Encrypt<COM = ()>: Types {
    /// Encrypts `plaintext` with the `encryption_key` and the one-time encryption `nonce`.
    fn encrypt(
        &self,
        encryption_key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext;
}

/// Decryption Types
pub trait DecryptionTypes: Types {
    /// Decryption Key Type
    type DecryptionKey;

    /// Decrypted Plaintext Type
    type DecryptedPlaintext;
}

///
pub type DecryptionKey<E> = <E as DecryptionTypes>::DecryptionKey;

///
pub type DecryptedPlaintext<E> = <E as DecryptionTypes>::DecryptedPlaintext;

/// Decryption Key Derivation
pub trait Derive<COM = ()>: DecryptionTypes {
    /// Derives a [`DecryptionKey`] from `encryption_key`.
    fn derive(&self, encryption_key: &Self::Key, compiler: &mut COM) -> Self::DecryptionKey;
}

/// Decryption
pub trait Decrypt<COM = ()>: DecryptionTypes {
    /// Decrypts the `ciphertext` with `decryption_key`.
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext;
}

/// Hybrid Encryption
pub mod hybrid {
    use super::*;

    ///
    pub trait KeyAgreementScheme {
        ///
        type SecretKey;

        ///
        type PublicKey;

        ///
        type SharedSecret;

        ///
        fn derive(&self, secret_key: &Self::SecretKey) -> Self::PublicKey;

        ///
        fn agree(
            &self,
            secret_key: &Self::SecretKey,
            public_key: &Self::PublicKey,
        ) -> Self::SharedSecret;
    }

    ///
    pub struct Hybrid<K, E>
    where
        K: KeyAgreementScheme,
        E: Types<Key = K::SharedSecret>,
    {
        ///
        pub key_agreement_scheme: K,

        ///
        pub encryption_scheme: E,
    }

    ///
    pub type EncryptionKey<K> = <K as KeyAgreementScheme>::PublicKey;

    ///
    pub type DecryptionKey<K> = <K as KeyAgreementScheme>::SecretKey;

    ///
    pub struct Nonce<K, E>
    where
        K: KeyAgreementScheme,
        E: Types<Key = K::SharedSecret>,
    {
        ///
        pub ephemeral_secret_key: K::SecretKey,

        ///
        pub nonce: E::Nonce,
    }

    ///
    pub struct Ciphertext<K, E>
    where
        K: KeyAgreementScheme,
        E: Types<Key = K::SharedSecret>,
    {
        ///
        pub ephemeral_public_key: K::PublicKey,

        ///
        pub ciphertext: E::Ciphertext,
    }

    impl<K, E> Types for Hybrid<K, E>
    where
        K: KeyAgreementScheme,
        E: Types<Key = K::SharedSecret>,
    {
        type Key = EncryptionKey<K>;
        type Nonce = Nonce<K, E>;
        type Plaintext = Plaintext<E>;
        type Ciphertext = Ciphertext<K, E>;
    }

    impl<K, E> DecryptionTypes for Hybrid<K, E>
    where
        K: KeyAgreementScheme,
        E: Types<Key = K::SharedSecret>,
    {
        type DecryptionKey = DecryptionKey<K>;
        type DecryptedPlaintext = Plaintext<E>;
    }

    impl<K, E> Encrypt for Hybrid<K, E>
    where
        K: KeyAgreementScheme,
        E: Encrypt<Key = K::SharedSecret>,
    {
        #[inline]
        fn encrypt(
            &self,
            encryption_key: &Self::Key,
            nonce: &Self::Nonce,
            plaintext: &Self::Plaintext,
            compiler: &mut (),
        ) -> Self::Ciphertext {
            Ciphertext {
                ephemeral_public_key: self
                    .key_agreement_scheme
                    .derive(&nonce.ephemeral_secret_key),
                ciphertext: self.encryption_scheme.encrypt(
                    &self
                        .key_agreement_scheme
                        .agree(&nonce.ephemeral_secret_key, encryption_key),
                    &nonce.nonce,
                    plaintext,
                    compiler,
                ),
            }
        }
    }

    impl<K, E> Decrypt for Hybrid<K, E>
    where
        K: KeyAgreementScheme,
        E: Decrypt<
            Key = K::SharedSecret,
            DecryptionKey = K::SharedSecret,
            DecryptedPlaintext = <E as Types>::Plaintext,
        >,
    {
        #[inline]
        fn decrypt(
            &self,
            decryption_key: &Self::DecryptionKey,
            ciphertext: &Self::Ciphertext,
            compiler: &mut (),
        ) -> Self::DecryptedPlaintext {
            self.encryption_scheme.decrypt(
                &self
                    .key_agreement_scheme
                    .agree(decryption_key, &ciphertext.ephemeral_public_key),
                &ciphertext.ciphertext,
                compiler,
            )
        }
    }
}
