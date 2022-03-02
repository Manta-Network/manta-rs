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

//! Symmetric Encryption

use core::marker::PhantomData;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Symmetric Key Encryption Scheme
///
/// # Specification
///
/// All implementations of this trait must adhere to the following properties:
///
/// 1. **Invertibility**: For all possible inputs, the following function returns `true`:
///
///     ```text
///     fn invertibility(key: Key, plaintext: Plaintext) -> bool {
///         matches!(decrypt(key, &encrypt(key, plaintext.clone())), Some(p) if p == plaintext)
///     }
///     ```
pub trait SymmetricKeyEncryptionScheme {
    /// Encryption/Decryption Key Type
    type Key;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;

    /// Encrypts `plaintext` using `key`.
    fn encrypt(key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext;

    /// Tries to decrypt `ciphertext` using `key`.
    fn decrypt(key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext>;
}

/// Mapped Symmetric Encryption Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde")
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Map<S, P = <S as SymmetricKeyEncryptionScheme>::Plaintext>(PhantomData<(S, P)>)
where
    S: SymmetricKeyEncryptionScheme,
    P: Into<S::Plaintext> + TryFrom<S::Plaintext>;

impl<S, P> SymmetricKeyEncryptionScheme for Map<S, P>
where
    S: SymmetricKeyEncryptionScheme,
    P: Into<S::Plaintext> + TryFrom<S::Plaintext>,
{
    type Key = S::Key;
    type Plaintext = P;
    type Ciphertext = S::Ciphertext;

    #[inline]
    fn encrypt(key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
        S::encrypt(key, plaintext.into())
    }

    #[inline]
    fn decrypt(key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
        S::decrypt(key, ciphertext).and_then(move |p| p.try_into().ok())
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use core::fmt::Debug;

    /// Tests if symmetric encryption of `plaintext` using `key` returns the same plaintext on
    /// decryption.
    #[inline]
    pub fn encryption<S>(key: S::Key, plaintext: S::Plaintext)
    where
        S: SymmetricKeyEncryptionScheme,
        S::Key: Clone,
        S::Plaintext: Clone + Debug + PartialEq,
    {
        assert_eq!(
            S::decrypt(key.clone(), &S::encrypt(key, plaintext.clone()))
                .expect("Decryption of encrypted message should have succeeded."),
            plaintext,
            "Plaintext should have matched decrypted-encrypted plaintext."
        )
    }
}
