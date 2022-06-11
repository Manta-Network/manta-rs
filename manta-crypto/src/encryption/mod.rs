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
pub trait EncryptionTypes: EncryptionKeyType + HeaderType + CiphertextType {
    /// Randomness Type
    type Randomness;

    /// Plaintext Type
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

/// Decryption
pub trait DecryptionTypes: DecryptionKeyType + HeaderType + CiphertextType {
    /// Decrypted Plaintext Type
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
