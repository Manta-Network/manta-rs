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
//!
//! The encryption abstractions are organized into a two categories, a set of type `trait`s and a
//! set of behavior `trait`s which require those types to be implemented. See the [`Encrypt`] and
//! [`Decrypt`] for more.

use core::{fmt::Debug, hash::Hash};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod hybrid;

/// Encryption Header
///
/// The encryption header contains information that must be available at both encryption and
/// decryption. Common headers include nonces and associated data, but cannot, for example, include
/// private randomness that is only available at encryption. In that case, one should use the
/// [`Randomness`] type. The header is also not encrypted as a consequence of being available at
/// both encryption and decryption, only the [`Plaintext`] is encrypted. See [`EncryptionTypes`] for
/// more details on types that are required for encryption.
///
/// [`Randomness`]: EncryptionTypes::Randomness
/// [`Plaintext`]: EncryptionTypes::Plaintext
pub trait HeaderType {
    /// Header Type
    type Header;
}

impl<T> HeaderType for &T
where
    T: HeaderType,
{
    type Header = T::Header;
}

/// Ciphertext
///
/// The ciphertext type represents the piece of the encrypt-decrypt interface that contains the
/// hidden information that can be created by encryption and is required for opening by decryption.
/// For [`hybrid`] and/or authenticating protocols this will also include ephemeral keys, tags, or
/// other metadata, not just the raw ciphertext. See the [`Encrypt::encrypt`] and
/// [`Decrypt::decrypt`] methods for more.
pub trait CiphertextType {
    /// Ciphertext Type
    type Ciphertext;
}

impl<T> CiphertextType for &T
where
    T: CiphertextType,
{
    type Ciphertext = T::Ciphertext;
}

/// Encryption Key
///
/// The encryption key is the information required to produce a valid ciphertext that is targeted
/// towards some [`DecryptionKey`](DecryptionKeyType::DecryptionKey). In the case when the
/// decryption key is linked by some computable protocol to the encryption key, [`Derive`] should be
/// implemented to fascilitate this derivation.
pub trait EncryptionKeyType {
    /// Encryption Key Type
    type EncryptionKey;
}

impl<T> EncryptionKeyType for &T
where
    T: EncryptionKeyType,
{
    type EncryptionKey = T::EncryptionKey;
}

/// Decryption Key
///
/// The decryption key is the information required to open a valid ciphertext that was encrypted
/// with the [`EncryptionKey`](EncryptionKeyType::EncryptionKey) that was targeted towards it. In
/// the case when the decryption key is linked by some computable protocol to the encryption key,
/// [`Derive`] should be implemented to fascilitate this derivation.
pub trait DecryptionKeyType {
    /// Decryption Key Type
    type DecryptionKey;
}

impl<T> DecryptionKeyType for &T
where
    T: DecryptionKeyType,
{
    type DecryptionKey = T::DecryptionKey;
}

/// Decryption Key Derivation
///
/// For protocols that can derive the [`EncryptionKey`] from the [`DecryptionKey`], this `trait` can
/// be used to specify the derivation algorithm. The [`DecryptionKey`] should be kept secret
/// relative to the [`EncryptionKey`] so if they are the same key, then some key exchange protocol
/// should be used to derive the [`DecryptionKey`] as some shared secret. See [`hybrid`] for more.
///
/// [`EncryptionKey`]: EncryptionKeyType::EncryptionKey
/// [`DecryptionKey`]: DecryptionKeyType::DecryptionKey
pub trait Derive<COM = ()>: EncryptionKeyType + DecryptionKeyType {
    /// Derives an [`EncryptionKey`](EncryptionKeyType::EncryptionKey) from `decryption_key`.
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey;
}

impl<T, COM> Derive<COM> for &T
where
    T: Derive<COM>,
{
    #[inline]
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey {
        (*self).derive(decryption_key, compiler)
    }
}

/// Encryption Types
///
/// This `trait` encapsulates all the types required for [`Encrypt::encrypt`].
pub trait EncryptionTypes: EncryptionKeyType + HeaderType + CiphertextType {
    /// Randomness Type
    ///
    /// The randomness type allows us to inject some extra randomness to hide repeated encryptions
    /// with the same key and same plaintext, independent of the nonce stored in the [`Header`]. In
    /// this case, note that [`Randomness`](Self::Randomness) is not available to the
    /// [`Decrypt::decrypt`] method.
    type Randomness;

    /// Plaintext Type
    ///
    /// The core payload of the encryption/decryption protocol. All the information in the plaintext
    /// should be kept secret and not be deducible from the [`Ciphertext`]. For associated data that
    /// does not go in the [`Ciphertext`] use [`Header`] instead.
    ///
    /// [`Ciphertext`]: CiphertextType::Ciphertext
    /// [`Header`]: HeaderType::Header
    type Plaintext;
}

impl<T> EncryptionTypes for &T
where
    T: EncryptionTypes,
{
    type Randomness = T::Randomness;
    type Plaintext = T::Plaintext;
}

/// Encryption
pub trait Encrypt<COM = ()>: EncryptionTypes {
    /// Encrypts `plaintext` with the `encryption_key` and the one-time encryption `randomness`,
    /// including `header`, but not necessarily encrypting it.
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        randomness: &Self::Randomness,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext;
}

impl<T, COM> Encrypt<COM> for &T
where
    T: Encrypt<COM>,
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
        (*self).encrypt(encryption_key, randomness, header, plaintext, compiler)
    }
}

/// Decryption Types
///
/// This `trait` encapsulates all the types required for [`Decrypt::decrypt`].
pub trait DecryptionTypes: DecryptionKeyType + HeaderType + CiphertextType {
    /// Decrypted Plaintext Type
    ///
    /// For decryption, we not only get out some data resembling the [`Plaintext`], but also
    /// authentication tags and other metadata in order to determine if the decryption succeeded if
    /// it is fallible. In general, we cannot assume that [`DecryptedPlaintext`] and [`Plaintext`]
    /// are the same type or if they are the same type, are the same value.
    ///
    /// [`Plaintext`]: EncryptionTypes::Plaintext
    /// [`DecryptedPlaintext`]: Self::DecryptedPlaintext
    type DecryptedPlaintext;
}

impl<T> DecryptionTypes for &T
where
    T: DecryptionTypes,
{
    type DecryptedPlaintext = T::DecryptedPlaintext;
}

/// Decryption
pub trait Decrypt<COM = ()>: DecryptionTypes {
    /// Decrypts the `ciphertext` with `decryption_key`.
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext;
}

impl<T, COM> Decrypt<COM> for &T
where
    T: Decrypt<COM>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        (*self).decrypt(decryption_key, header, ciphertext, compiler)
    }
}

/// Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "E::Header: Clone, E::Plaintext: Clone"),
    Copy(bound = "E::Header: Copy, E::Plaintext: Copy"),
    Debug(bound = "E::Header: Debug, E::Plaintext: Debug"),
    Default(bound = "E::Header: Default, E::Plaintext: Default"),
    Eq(bound = "E::Header: Eq, E::Plaintext: Eq"),
    Hash(bound = "E::Header: Hash, E::Plaintext: Hash"),
    PartialEq(bound = "E::Header: PartialEq, E::Plaintext: PartialEq")
)]
pub struct Message<E>
where
    E: HeaderType + CiphertextType,
{
    /// Header
    pub header: E::Header,

    /// Plaintext
    pub plaintext: E::Plaintext,
}

/// Encrypted Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "E::Header: Clone, E::Ciphertext: Clone"),
    Copy(bound = "E::Header: Copy, E::Ciphertext: Copy"),
    Debug(bound = "E::Header: Debug, E::Ciphertext: Debug"),
    Default(bound = "E::Header: Default, E::Ciphertext: Default"),
    Eq(bound = "E::Header: Eq, E::Ciphertext: Eq"),
    Hash(bound = "E::Header: Hash, E::Ciphertext: Hash"),
    PartialEq(bound = "E::Header: PartialEq, E::Ciphertext: PartialEq")
)]
pub struct EncryptedMessage<E>
where
    E: HeaderType + CiphertextType,
{
    /// Header
    pub header: E::Header,

    /// Ciphertext
    pub ciphertext: E::Ciphertext,
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;

    /// Tests if encryption of `plaintext` using `encryption_key` and `randomness` returns the
    /// original `plaintext` on decryption using `decryption_key`. The `assert_same` function is
    /// used to assert that the two plaintexts are the same.
    #[inline]
    pub fn encryption<E, F>(
        cipher: &E,
        encryption_key: &E::EncryptionKey,
        decryption_key: &E::DecryptionKey,
        randomness: &E::Randomness,
        header: &E::Header,
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
                header,
                &cipher.encrypt(encryption_key, randomness, header, plaintext, &mut ()),
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
        randomness: &E::Randomness,
        header: &E::Header,
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
            randomness,
            header,
            plaintext,
            assert_same,
        )
    }
}
