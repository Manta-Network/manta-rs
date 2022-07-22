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
//! Signature Scheme for trusted setup.
/// TODO: Shall we use `manta_crypto::signature` instead?
use crate::ceremony::CeremonyError;

/// Public Key of participant
pub trait HasPublicKey {
    /// Public Key of participant
    type PublicKey;

    /// Returns the public key of the participant.
    fn public_key(&self) -> Self::PublicKey;
}

/// Signature Scheme types
pub trait Types {
    /// Public Key
    type PublicKey;

    /// Private Key
    type PrivateKey;

    /// Signature
    type Signature;
}

/// Message Verifier
pub trait Verifier: Types {
    /// Verify a message is correct
    fn verify<M>(
        message: &M,
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> Result<(), CeremonyError>
    where
        M: Verify<Self> + ?Sized,
    {
        message.verify_integrity(public_key, signature)
    }
}

/// Message Signer
pub trait Signer: Types {
    /// Sign a message
    fn sign<M>(
        message: &M,
        public_key: &Self::PublicKey,
        private_key: &Self::PrivateKey,
    ) -> Result<Self::Signature, CeremonyError>
    where
        M: Sign<Self> + ?Sized,
    {
        message.sign(public_key, private_key)
    }
}

/// Verifiable Message
pub trait Verify<S>
where
    S: Verifier + ?Sized,
{
    /// Verify the integrity of the message
    fn verify_integrity(
        &self,
        public_key: &S::PublicKey,
        signature: &S::Signature,
    ) -> Result<(), CeremonyError>;
}

/// Signable Message
pub trait Sign<S>
where
    S: Signer + ?Sized,
{
    /// Sign the message
    fn sign(
        &self,
        public_key: &S::PublicKey,
        private_key: &S::PrivateKey,
    ) -> Result<S::Signature, CeremonyError>;
}
