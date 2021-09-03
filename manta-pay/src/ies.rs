// Copyright 2019-2021 Manta Network.
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

//! IES Implementation

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Nonce,
};
use ark_std::rand::{CryptoRng, RngCore};
use blake2::{Blake2s, Digest};
use generic_array::GenericArray;
use manta_accounting::Asset;
use manta_codec::{ScaleDecode, ScaleEncode};
use manta_crypto::{
    ies::{self, KeyPair},
    IntegratedEncryptionScheme,
};
use manta_util::try_into_array_unchecked;
use x25519_dalek::{EphemeralSecret, PublicKey as PubKey, StaticSecret};

/// Public Key Type
pub type PublicKey = [u8; 32];

/// Secret Key Type
pub type SecretKey = [u8; 32];

/// Ciphertext Type
// FIXME: this should be automatically calculated from [`Asset`]
// FIXME: is this calculation correct? how do we know?
pub type Ciphertext = [u8; Asset::SIZE + 16];

/// Ephemeral Public Key Type
pub type EphemeralPublicKey = PublicKey;

/// Augmented Ciphertext
pub struct AugmentedCiphertext {
    /// Base Ciphertext
    pub ciphertext: Ciphertext,

    /// Ephemeral Public Key
    pub ephemeral_public_key: EphemeralPublicKey,
}

impl AugmentedCiphertext {
    /// Builds a new [`AugmentedCiphertext`] from `ciphertext` and `ephemeral_public_key`.
    #[inline]
    pub const fn new(ciphertext: Ciphertext, ephemeral_public_key: EphemeralPublicKey) -> Self {
        Self {
            ciphertext,
            ephemeral_public_key,
        }
    }
}

/// Encrypted Message for [`IES`]
pub type EncryptedMessage = ies::EncryptedMessage<IES>;

/// Implementation of [`IntegratedEncryptionScheme`]
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, ScaleDecode, ScaleEncode,
)]
pub struct IES;

impl IES {
    /// Encryption/Decryption Nonce
    const NONCE: &'static [u8] = b"manta rocks!";

    /// KDF Salt
    const KDF_SALT: &'static [u8] = b"manta kdf instantiated with blake2s hash function";

    /// Runs `blake2s::hkdf_extract(salt, seed)` with a fixed salt.
    fn blake2s_kdf(input: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2s::new();
        hasher.update([input, Self::KDF_SALT].concat());
        try_into_array_unchecked(hasher.finalize())
    }
}

impl IntegratedEncryptionScheme for IES {
    type PublicKey = PublicKey;

    type SecretKey = SecretKey;

    type Plaintext = Asset;

    type Ciphertext = AugmentedCiphertext;

    type Error = aes_gcm::Error;

    #[inline]
    fn keygen<R>(rng: &mut R) -> KeyPair<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let sk = StaticSecret::new(rng);
        let pk = PubKey::from(&sk);
        KeyPair::new(pk.to_bytes(), sk.to_bytes())
    }

    fn encrypt<R>(
        plaintext: Self::Plaintext,
        public_key: Self::PublicKey,
        rng: &mut R,
    ) -> Result<EncryptedMessage, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let ephemeral_secret_key = EphemeralSecret::new(rng);
        let ephemeral_public_key = PubKey::from(&ephemeral_secret_key);
        let shared_secret = ephemeral_secret_key.diffie_hellman(&PubKey::from(public_key));
        let ss = Self::blake2s_kdf(&shared_secret.to_bytes());
        let aes_key = GenericArray::from_slice(&ss);

        // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
        let ciphertext = Aes256Gcm::new(aes_key).encrypt(
            Nonce::from_slice(Self::NONCE),
            plaintext.into_bytes().as_ref(),
        )?;

        Ok(EncryptedMessage::new(AugmentedCiphertext::new(
            try_into_array_unchecked(ciphertext),
            ephemeral_public_key.to_bytes(),
        )))
    }

    fn decrypt(
        ciphertext: Self::Ciphertext,
        secret_key: Self::SecretKey,
    ) -> Result<Self::Plaintext, Self::Error> {
        let sk = StaticSecret::from(secret_key);
        let shared_secret = sk.diffie_hellman(&PubKey::from(ciphertext.ephemeral_public_key));
        let ss = Self::blake2s_kdf(&shared_secret.to_bytes());
        let aes_key = GenericArray::from_slice(&ss);

        // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
        let plaintext = Aes256Gcm::new(aes_key).decrypt(
            Nonce::from_slice(Self::NONCE),
            ciphertext.ciphertext.as_ref(),
        )?;

        Ok(Asset::from_bytes(try_into_array_unchecked(
            &plaintext[..Asset::SIZE],
        )))
    }
}
