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

/// Encryption Types
pub trait Types {
    /// Encryption Key Type
    type EncryptionKey;

    /// Decryption Key Type
    type DecryptionKey;

    /// Encryption Nonce
    type Nonce;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;

    /// Decrypted Plaintext Type
    type DecryptedPlaintext;
}

/// Decryption Key Derivation
pub trait Derive<COM = ()>: Types {
    /// Derives a [`DecryptionKey`] from `encryption_key`.
    fn derive(
        &self,
        encryption_key: &Self::EncryptionKey,
        compiler: &mut COM,
    ) -> Self::DecryptionKey;
}

/// Encryption
pub trait Encrypt<COM = ()>: Types {
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
pub trait Decrypt<COM = ()>: Types {
    /// Decrypts the `ciphertext` with `decryption_key`.
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext;
}
