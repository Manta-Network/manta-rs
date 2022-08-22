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

//! Encryption Implementations

pub mod aes;

/// Testing Suite
#[cfg(test)]
mod test {
    use crate::config::NoteSymmetricEncryptionScheme;
    use manta_crypto::{
        encryption,
        rand::{OsRng, Rand},
    };

    /// Tests if symmetric encryption of [`Note`] decrypts properly.
    #[test]
    fn note_symmetric_encryption() {
        let mut rng = OsRng;
        let key = rng.gen();
        encryption::test::correctness::<NoteSymmetricEncryptionScheme, _>(
            &rng.gen(),
            &key,
            &key,
            &(),
            &(),
            &rng.gen(),
            |plaintext, decrypted_plaintext| {
                assert_eq!(
                    plaintext,
                    &decrypted_plaintext.expect("Unable to decrypt ciphertext.")
                );
            },
        );
    }

    /// Checks that trying to decrypt a ciphertext under an invalid key returns `None`.
    #[test]
    fn invalid_key_symmetric_check() {
        let mut rng = OsRng;
        let encryption_key = rng.gen();
        let invalid_decryption_key = rng.gen();
        encryption::test::correctness::<NoteSymmetricEncryptionScheme, _>(
            &rng.gen(),
            &encryption_key,
            &invalid_decryption_key,
            &(),
            &(),
            &rng.gen(),
            |_, decrypted_plaintext| {
                assert!(decrypted_plaintext.is_none());
            },
        );
    }

    /*
    // TODO: Make this work. Problem: Ciphertext does not implement Sample.
    /// Checks that randomly generated ciphertexts are always invalid.
    #[test]
    fn invalid_ciphertext_symmetric_check() {
        let mut rng = OsRng;
        let decryption_key = rng.gen();
        encryption::test::ciphertext_check::<NoteSymmetricEncryptionScheme, _>(
            &rng.gen(),
            &decryption_key,
            &(),
            &rng.gen(),
            |decrypted_plaintext| {
                assert!(decrypted_plaintext.is_none());
            },
        );
    }
    */
}
