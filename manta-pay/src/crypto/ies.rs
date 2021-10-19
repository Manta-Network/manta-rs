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

// FIXME: Don't use raw bytes as secret and public key.
// FIXME: Make sure secret keys are protected.

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Nonce,
};
use blake2::{Blake2s, Digest};
use generic_array::GenericArray;
use manta_accounting::Asset;
use manta_crypto::{
    ies::{self, KeyPair},
    rand::{CryptoRng, RngCore},
    IntegratedEncryptionScheme,
};
use manta_util::into_array_unchecked;
use x25519_dalek::{EphemeralSecret, PublicKey as PubKey, StaticSecret};

/// Public Key Type
pub type PublicKey = [u8; 32];

/// Secret Key Type
pub type SecretKey = [u8; 32];

/// `GCM` Tag Size
#[allow(clippy::cast_possible_truncation)] // NOTE: GCM Tag Size should be smaller than `2^32`.
const GCM_TAG_SIZE: usize = (aes_gcm::C_MAX - aes_gcm::P_MAX) as usize;

/// Asset Ciphertext Type
pub type AssetCiphertext = [u8; Asset::SIZE + GCM_TAG_SIZE];

/// Ephemeral Public Key Type
pub type EphemeralPublicKey = PublicKey;

/// Augmented Asset Ciphertext
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AugmentedAssetCiphertext {
    /// Asset Ciphertext
    pub asset_ciphertext: AssetCiphertext,

    /// Ephemeral Public Key
    pub ephemeral_public_key: EphemeralPublicKey,
}

impl AugmentedAssetCiphertext {
    /// Builds a new [`AugmentedAssetCiphertext`] from `asset_ciphertext`
    /// and `ephemeral_public_key`.
    #[inline]
    pub const fn new(
        asset_ciphertext: AssetCiphertext,
        ephemeral_public_key: EphemeralPublicKey,
    ) -> Self {
        Self {
            asset_ciphertext,
            ephemeral_public_key,
        }
    }
}

/// Encrypted Message for [`IES`]
pub type EncryptedAsset = ies::EncryptedMessage<IES>;

/// Implementation of [`IntegratedEncryptionScheme`]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IES;

impl IES {
    /// Encryption/Decryption Nonce
    const NONCE: &'static [u8] = b"manta rocks!";

    /// KDF Salt
    const KDF_SALT: &'static [u8] = b"manta kdf instantiated with blake2s hash function";

    /// Runs `blake2s::hkdf_extract(salt, seed)` with a fixed salt.
    #[inline]
    fn blake2s_kdf(input: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2s::new();
        hasher.update(input);
        hasher.update(Self::KDF_SALT);
        into_array_unchecked(hasher.finalize())
    }
}

impl IntegratedEncryptionScheme for IES {
    type PublicKey = PublicKey;

    type SecretKey = SecretKey;

    type Plaintext = Asset;

    type Ciphertext = AugmentedAssetCiphertext;

    type Error = aes_gcm::Error;

    #[inline]
    fn generate_keys<R>(rng: &mut R) -> KeyPair<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let sk = StaticSecret::new(rng);
        let pk = PubKey::from(&sk);
        KeyPair::new(pk.to_bytes(), sk.to_bytes())
    }

    #[inline]
    fn generate_public_key<R>(rng: &mut R) -> ies::PublicKey<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        // TODO: Is there an even more efficient way to do this?
        ies::PublicKey::new(PubKey::from(&StaticSecret::new(rng)).to_bytes())
    }

    #[inline]
    fn generate_secret_key<R>(rng: &mut R) -> ies::SecretKey<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        ies::SecretKey::new(StaticSecret::new(rng).to_bytes())
    }

    fn encrypt<R>(
        plaintext: &Self::Plaintext,
        public_key: Self::PublicKey,
        rng: &mut R,
    ) -> Result<EncryptedAsset, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let ephemeral_secret_key = EphemeralSecret::new(rng);
        let ephemeral_public_key = PubKey::from(&ephemeral_secret_key);
        let shared_secret = Self::blake2s_kdf(
            &ephemeral_secret_key
                .diffie_hellman(&public_key.into())
                .to_bytes(),
        );

        // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
        let asset_ciphertext = Aes256Gcm::new(GenericArray::from_slice(&shared_secret)).encrypt(
            Nonce::from_slice(Self::NONCE),
            plaintext.into_bytes().as_ref(),
        )?;

        Ok(EncryptedAsset::new(AugmentedAssetCiphertext::new(
            into_array_unchecked(asset_ciphertext),
            ephemeral_public_key.to_bytes(),
        )))
    }

    fn decrypt(
        ciphertext: &Self::Ciphertext,
        secret_key: Self::SecretKey,
    ) -> Result<Self::Plaintext, Self::Error> {
        let shared_secret = Self::blake2s_kdf(
            &StaticSecret::from(secret_key)
                .diffie_hellman(&ciphertext.ephemeral_public_key.into())
                .to_bytes(),
        );

        // SAFETY: Using a deterministic nonce is ok since we never reuse keys.
        let plaintext = Aes256Gcm::new(GenericArray::from_slice(&shared_secret)).decrypt(
            Nonce::from_slice(Self::NONCE),
            ciphertext.asset_ciphertext.as_ref(),
        )?;

        Ok(Asset::from_bytes(into_array_unchecked(
            &plaintext[..Asset::SIZE],
        )))
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use manta_crypto::{ies::test as ies_test, rand::Rand};
    use rand::thread_rng;

    /// Tests encryption/decryption of a random asset.
    #[test]
    fn encryption_decryption() {
        let mut rng = thread_rng();
        ies_test::assert_decryption_of_encryption::<IES, _>(&rng.gen(), &mut rng);
    }
}
