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

//! Hybrid Public-Key Encryption

use crate::{
    encryption::{
        CiphertextType, Decrypt, DecryptionKeyType, DecryptionTypes, Derive, Encrypt,
        EncryptionKeyType, EncryptionTypes, HeaderType,
    },
    key,
};
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

/// Encryption Randomness
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K::SecretKey: Clone, E::Randomness: Clone"),
    Copy(bound = "K::SecretKey: Copy, E::Randomness: Copy"),
    Debug(bound = "K::SecretKey: Debug, E::Randomness: Debug"),
    Default(bound = "K::SecretKey: Default, E::Randomness: Default"),
    Eq(bound = "K::SecretKey: Eq, E::Randomness: Eq"),
    Hash(bound = "K::SecretKey: Hash, E::Randomness: Hash"),
    PartialEq(bound = "K::SecretKey: PartialEq, E::Randomness: PartialEq")
)]
pub struct Randomness<K, E>
where
    K: key::agreement::Types,
    E: EncryptionTypes,
{
    /// Ephemeral Secret Key
    pub ephemeral_secret_key: K::SecretKey,

    /// Base Encryption Randomness
    pub randomness: E::Randomness,
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

impl<K, E> HeaderType for Hybrid<K, E>
where
    K: key::agreement::Types,
    E: HeaderType,
{
    type Header = E::Header;
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

impl<K, E> DecryptionKeyType for Hybrid<K, E>
where
    K: key::agreement::Types,
{
    type DecryptionKey = DecryptionKey<K>;
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

impl<K, E> EncryptionTypes for Hybrid<K, E>
where
    K: key::agreement::Types,
    E: EncryptionTypes,
{
    type Randomness = Randomness<K, E>;
    type Plaintext = E::Plaintext;
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
        randomness: &Self::Randomness,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext {
        Ciphertext {
            ephemeral_public_key: self
                .key_agreement_scheme
                .derive(&randomness.ephemeral_secret_key, compiler),
            ciphertext: self.encryption_scheme.encrypt(
                &self.key_agreement_scheme.agree(
                    encryption_key,
                    &randomness.ephemeral_secret_key,
                    compiler,
                ),
                &randomness.randomness,
                header,
                plaintext,
                compiler,
            ),
        }
    }
}

impl<K, E> DecryptionTypes for Hybrid<K, E>
where
    K: key::agreement::Types,
    E: DecryptionTypes,
{
    type DecryptedPlaintext = E::DecryptedPlaintext;
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
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        self.encryption_scheme.decrypt(
            &self.key_agreement_scheme.agree(
                &ciphertext.ephemeral_public_key,
                decryption_key,
                compiler,
            ),
            header,
            &ciphertext.ciphertext,
            compiler,
        )
    }
}
