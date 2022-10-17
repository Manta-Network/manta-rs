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

//! Manta Pay Cryptographic Primitives Implementations

pub mod constraint;
pub mod ecc;
/// Testing Suite
pub mod poseidon;

/// Testing Suite
#[cfg(test)]
mod test {
    use crate::config::utxo::v1::IncomingBaseEncryptionScheme;
    use manta_accounting::transfer::utxo::v1::IncomingPlaintext;
    use manta_crypto::{
        encryption::{self, EmptyHeader},
        rand::{OsRng, Rand},
    };

    // /// Tests if symmetric encryption of [`Note`] decrypts properly.
    // #[test]
    // fn note_symmetric_encryption() {
    //     let mut rng = OsRng;
    //     let key = rng.gen();
    //     encryption::test::correctness::<IncomingBaseEncryptionScheme, _>(
    //         &rng.gen(),
    //         &key,
    //         &key,
    //         &(),
    //         &(),
    //         &rng.gen(),
    //         |plaintext, decrypted_plaintext| {
    //             assert_eq!(
    //                 plaintext,
    //                 &decrypted_plaintext.expect("Unable to decrypt ciphertext.")
    //             );
    //         },
    //     );
    // }
    #[test]
    fn note_symmetric_encryption_100_000_times() {
        let mut rng = OsRng;
        let mut enc_vec = Vec::new();
        let mut dec_vec = Vec::new();

        let iterations = 100_000;

        for _ in 0..iterations {
            enc_vec.push(rng.gen());
            dec_vec.push(rng.gen());
        }

        encryption::test::decrypt_only::<IncomingBaseEncryptionScheme>(
            &rng.gen(),
            &enc_vec,
            &dec_vec,
            &(),
            &EmptyHeader::default(),
            &IncomingPlaintext::new(rng.gen(), rng.gen()),
            iterations,
        );
    }
}
