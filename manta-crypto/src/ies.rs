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

//! Integrated Encryption Schemes and Encrypted Messages

use ark_std::rand::{CryptoRng, RngCore};
use core::{fmt::Debug, hash::Hash};
use manta_codec::{ScaleDecode, ScaleEncode};

/// [`IntegratedEncryptionScheme`] Key Pair
#[derive(derivative::Derivative, ScaleDecode, ScaleEncode)]
#[derivative(
	Clone(bound = "I::PublicKey: Clone, I::SecretKey: Clone"),
	Copy(bound = "I::PublicKey: Copy, I::SecretKey: Copy"),
	Debug(bound = "I::PublicKey: Debug, I::SecretKey: Debug"),
	Default(bound = "I::PublicKey: Default, I::SecretKey: Default"),
	Eq(bound = "I::PublicKey: Eq, I::SecretKey: Eq"),
	Hash(bound = "I::PublicKey: Hash, I::SecretKey: Hash"),
	PartialEq(bound = "I::PublicKey: PartialEq, I::SecretKey: PartialEq")
)]
pub struct KeyPair<I: ?Sized>
where
	I: IntegratedEncryptionScheme,
{
	/// Public Key
	pub public: I::PublicKey,

	/// Secret Key
	pub secret: I::SecretKey,
}

impl<I> KeyPair<I>
where
	I: IntegratedEncryptionScheme,
{
	/// Builds a new [`KeyPair`] from a `public` key and a `secret` key.
	#[inline]
	pub fn new(public: I::PublicKey, secret: I::SecretKey) -> Self {
		Self { public, secret }
	}
}

/// Integrated Encryption Scheme Trait
pub trait IntegratedEncryptionScheme {
	/// Public Key Type
	type PublicKey;

	/// Secret Key Type
	type SecretKey;

	/// Plaintext Type
	type Plaintext;

	/// Ciphertext Type
	type Ciphertext;

	/// Encryption/Decryption Error Type
	type Error;

	/// Generates public/secret keypair.
	fn keygen<R>(rng: &mut R) -> KeyPair<Self>
	where
		R: CryptoRng + RngCore;

	/// Generates a new keypair and encrypts the `message`, generating an [`EncryptedMessage`],
	/// and returning the keypair.
	#[inline]
	fn keygen_encrypt<R>(
		message: &Self::Plaintext,
		rng: &mut R,
	) -> Result<(KeyPair<Self>, EncryptedMessage<Self>), Self::Error>
	where
		R: CryptoRng + RngCore,
	{
		let keypair = Self::keygen(rng);
		let encrypted_message = Self::encrypt(message, &keypair.public, rng)?;
		Ok((keypair, encrypted_message))
	}

	/// Encrypts the `message` with `pk`, generating an [`EncryptedMessage`].
	fn encrypt<R>(
		message: &Self::Plaintext,
		pk: &Self::PublicKey,
		rng: &mut R,
	) -> Result<EncryptedMessage<Self>, Self::Error>
	where
		R: CryptoRng + RngCore;

	/// Decrypts the `message` with `sk`.
	fn decrypt(
		message: &EncryptedMessage<Self>,
		sk: &Self::SecretKey,
	) -> Result<Self::Plaintext, Self::Error>;
}

/// Encrypted Message
#[derive(derivative::Derivative, ScaleDecode, ScaleEncode)]
#[derivative(
	Clone(bound = "I::Ciphertext: Clone, I::PublicKey: Clone"),
	Copy(bound = "I::Ciphertext: Copy, I::PublicKey: Copy"),
	Debug(bound = "I::Ciphertext: Debug, I::PublicKey: Debug"),
	Default(bound = "I::Ciphertext: Default, I::PublicKey: Default"),
	Eq(bound = "I::Ciphertext: Eq, I::PublicKey: Eq"),
	Hash(bound = "I::Ciphertext: Hash, I::PublicKey: Hash"),
	PartialEq(bound = "I::Ciphertext: PartialEq, I::PublicKey: PartialEq")
)]
pub struct EncryptedMessage<I: ?Sized>
where
	I: IntegratedEncryptionScheme,
{
	/// Ciphertext of the Message
	pub ciphertext: I::Ciphertext,

	/// Ephemeral Public Key
	pub ephemeral_public_key: I::PublicKey,
}

impl<I> EncryptedMessage<I>
where
	I: IntegratedEncryptionScheme,
{
	/// Builds a new [`EncryptedMessage`] from [`I::Ciphertext`] and an ephemeral [`I::PublicKey`].
	///
	/// [`I::Ciphertext`]: IntegratedEncryptionScheme::Ciphertext
	/// [`I::PublicKey`]: IntegratedEncryptionScheme::PublicKey
	#[inline]
	pub fn new(ciphertext: I::Ciphertext, ephemeral_public_key: I::PublicKey) -> Self {
		Self {
			ciphertext,
			ephemeral_public_key,
		}
	}

	/// Generates a new keypair and encrypts the `message`, generating an [`EncryptedMessage`],
	/// and returning the keypair.
	#[inline]
	pub fn keygen_encrypt<R>(
		message: &I::Plaintext,
		rng: &mut R,
	) -> Result<(KeyPair<I>, Self), I::Error>
	where
		R: CryptoRng + RngCore,
	{
		I::keygen_encrypt(message, rng)
	}

	/// Encrypts the `message` with `pk`, generating an [`EncryptedMessage`].
	#[inline]
	pub fn encrypt<R>(
		message: &I::Plaintext,
		pk: &I::PublicKey,
		rng: &mut R,
	) -> Result<Self, I::Error>
	where
		R: CryptoRng + RngCore,
	{
		I::encrypt(message, pk, rng)
	}

	/// Decrypts the `message` with `sk`.
	#[inline]
	pub fn decrypt(&self, sk: &I::SecretKey) -> Result<I::Plaintext, I::Error> {
		I::decrypt(self, sk)
	}
}
