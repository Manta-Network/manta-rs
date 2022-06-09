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

/// Ciphertext
pub trait CiphertextType {
    /// Ciphertext Type
    type Ciphertext;
}

/// Ciphertext Type
pub type Ciphertext<E> = <E as CiphertextType>::Ciphertext;

/// Encryption Key
pub trait EncryptionKeyType {
    /// Encryption Key Type
    type EncryptionKey;
}

/// Encryption Key Type
pub type EncryptionKey<E> = <E as EncryptionKeyType>::EncryptionKey;

/// Encryption Types
pub trait EncryptionTypes: EncryptionKeyType + CiphertextType {
    /// Nonce Type
    type Nonce;

    /// Plaintext Type
    type Plaintext;
}

/// Nonce Type
pub type Nonce<E> = <E as EncryptionTypes>::Nonce;

/// Plaintext Type
pub type Plaintext<E> = <E as EncryptionTypes>::Plaintext;

/// Decryption Key
pub trait DecryptionKeyType {
    /// Decryption Key Type
    type DecryptionKey;
}

/// Decryption Key Type
pub type DecryptionKey<E> = <E as DecryptionKeyType>::DecryptionKey;

/// Decryption Types
pub trait DecryptionTypes: DecryptionKeyType + CiphertextType {
    /// Decrypted Plaintext
    type DecryptedPlaintext;
}

/// Decrypted Plaintext Type
pub type DecryptedPlaintext<E> = <E as DecryptionTypes>::DecryptedPlaintext;

/// Decryption Key Derivation
pub trait Derive<COM = ()>: EncryptionKeyType + DecryptionKeyType {
    /// Derives an [`EncryptionKey`] from `decryption_key`.
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey;
}

/// Encryption
pub trait Encrypt<COM = ()>: EncryptionTypes {
    /// Encrypts `plaintext` with the `encryption_key` and the one-time encryption `nonce`.
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        nonce: &Self::Nonce,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext;
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
    use crate::key;
    use core::{fmt::Debug, hash::Hash};

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// Hybrid Encryption Scheme
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde", deny_unknown_fields)
    )]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct Hybrid<K, E>
    where
        K: key::agreement::Types,
    {
        /// Key Agreement Scheme
        pub key_agreement_scheme: K,

        /// Base Encryption Scheme
        pub encryption_scheme: E,
    }

    /// Encryption Key
    pub type EncryptionKey<K> = <K as key::agreement::Types>::PublicKey;

    /// Decryption Key
    pub type DecryptionKey<K> = <K as key::agreement::Types>::SecretKey;

    /// Encryption Nonce
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde", deny_unknown_fields)
    )]
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = "K::SecretKey: Clone, E::Nonce: Clone"),
        Copy(bound = "K::SecretKey: Copy, E::Nonce: Copy"),
        Debug(bound = "K::SecretKey: Debug, E::Nonce: Debug"),
        Default(bound = "K::SecretKey: Default, E::Nonce: Default"),
        Eq(bound = "K::SecretKey: Eq, E::Nonce: Eq"),
        Hash(bound = "K::SecretKey: Hash, E::Nonce: Hash"),
        PartialEq(bound = "K::SecretKey: PartialEq, E::Nonce: PartialEq")
    )]
    pub struct Nonce<K, E>
    where
        K: key::agreement::Types,
        E: EncryptionTypes,
    {
        /// Ephemeral Secret Key
        pub ephemeral_secret_key: K::SecretKey,

        /// Base Encryption Nonce
        pub nonce: E::Nonce,
    }

    /// Full Ciphertext
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde", deny_unknown_fields)
    )]
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = "K::PublicKey: Clone, E::Ciphertext: Clone"),
        Copy(bound = "K::PublicKey: Copy, E::Ciphertext: Copy"),
        Debug(bound = "K::PublicKey: Debug, E::Ciphertext: Debug"),
        Default(bound = "K::PublicKey: Default, E::Ciphertext: Default"),
        Eq(bound = "K::PublicKey: Eq, E::Ciphertext: Eq"),
        Hash(bound = "K::PublicKey: Hash, E::Ciphertext: Hash"),
        PartialEq(bound = "K::PublicKey: PartialEq, E::Ciphertext: PartialEq")
    )]
    pub struct Ciphertext<K, E>
    where
        K: key::agreement::Types,
        E: CiphertextType,
    {
        /// Ephemeral Public Key
        pub ephemeral_public_key: K::PublicKey,

        /// Base Encryption Ciphertext
        pub ciphertext: E::Ciphertext,
    }

    impl<K, E> CiphertextType for Hybrid<K, E>
    where
        K: key::agreement::Types,
        E: CiphertextType,
    {
        type Ciphertext = Ciphertext<K, E>;
    }

    impl<K, E> EncryptionKeyType for Hybrid<K, E>
    where
        K: key::agreement::Types,
    {
        type EncryptionKey = EncryptionKey<K>;
    }

    impl<K, E> EncryptionTypes for Hybrid<K, E>
    where
        K: key::agreement::Types,
        E: EncryptionTypes,
    {
        type Nonce = Nonce<K, E>;
        type Plaintext = Plaintext<E>;
    }

    impl<K, E> DecryptionKeyType for Hybrid<K, E>
    where
        K: key::agreement::Types,
    {
        type DecryptionKey = DecryptionKey<K>;
    }

    impl<K, E> DecryptionTypes for Hybrid<K, E>
    where
        K: key::agreement::Types,
        E: DecryptionTypes,
    {
        type DecryptedPlaintext = DecryptedPlaintext<E>;
    }

    impl<K, E, COM> Derive<COM> for Hybrid<K, E>
    where
        K: key::agreement::Derive<COM>,
    {
        #[inline]
        fn derive(
            &self,
            decryption_key: &Self::DecryptionKey,
            compiler: &mut COM,
        ) -> Self::EncryptionKey {
            self.key_agreement_scheme.derive(decryption_key, compiler)
        }
    }

    impl<K, E, COM> Encrypt<COM> for Hybrid<K, E>
    where
        K: key::agreement::Derive<COM> + key::agreement::Agree<COM>,
        E: Encrypt<COM, EncryptionKey = K::SharedSecret>,
    {
        #[inline]
        fn encrypt(
            &self,
            encryption_key: &Self::EncryptionKey,
            nonce: &Self::Nonce,
            plaintext: &Self::Plaintext,
            compiler: &mut COM,
        ) -> Self::Ciphertext {
            Ciphertext {
                ephemeral_public_key: self
                    .key_agreement_scheme
                    .derive(&nonce.ephemeral_secret_key, compiler),
                ciphertext: self.encryption_scheme.encrypt(
                    &self.key_agreement_scheme.agree(
                        encryption_key,
                        &nonce.ephemeral_secret_key,
                        compiler,
                    ),
                    &nonce.nonce,
                    plaintext,
                    compiler,
                ),
            }
        }
    }

    impl<K, E, COM> Decrypt<COM> for Hybrid<K, E>
    where
        K: key::agreement::Agree<COM>,
        E: Decrypt<COM, DecryptionKey = K::SharedSecret>,
    {
        #[inline]
        fn decrypt(
            &self,
            decryption_key: &Self::DecryptionKey,
            ciphertext: &Self::Ciphertext,
            compiler: &mut COM,
        ) -> Self::DecryptedPlaintext {
            self.encryption_scheme.decrypt(
                &self.key_agreement_scheme.agree(
                    &ciphertext.ephemeral_public_key,
                    decryption_key,
                    compiler,
                ),
                &ciphertext.ciphertext,
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

    /// Tests if encryption of `plaintext` using `encryption_key` and `nonce` returns the original
    /// `plaintext` on decryption using `decryption_key`. The `assert_same` function is used to
    /// assert that the two plaintexts are the same.
    #[inline]
    pub fn encryption<E, F>(
        cipher: &E,
        encryption_key: &E::EncryptionKey,
        decryption_key: &E::DecryptionKey,
        nonce: &E::Nonce,
        plaintext: &E::Plaintext,
        assert_same: F,
    ) where
        E: Encrypt + Decrypt,
        F: FnOnce(&E::Plaintext, &E::DecryptedPlaintext),
    {
        assert_same(
            plaintext,
            &cipher.decrypt(
                decryption_key,
                &cipher.encrypt(encryption_key, nonce, plaintext, &mut ()),
                &mut (),
            ),
        )
    }

    /// Derives an [`EncryptionKey`](EncryptionKeyType::EncryptionKey) from `decryption_key` and
    /// then runs the [`encryption`] correctness assertion test.
    #[inline]
    pub fn derive_encryption<E, F>(
        cipher: &E,
        decryption_key: &E::DecryptionKey,
        nonce: &E::Nonce,
        plaintext: &E::Plaintext,
        assert_same: F,
    ) where
        E: Derive + Encrypt + Decrypt,
        F: FnOnce(&E::Plaintext, &E::DecryptedPlaintext),
    {
        encryption(
            cipher,
            &cipher.derive(decryption_key, &mut ()),
            decryption_key,
            nonce,
            plaintext,
            assert_same,
        )
    }
}
