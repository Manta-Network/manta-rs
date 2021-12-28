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

//! Cryptographic Key Primitives

/// Key Derivation Function
pub trait KeyDerivationFunction<J = ()> {
    /// Input Key Type
    type Key;

    /// Output Key Type
    type Output;

    /// Derives an output key from `secret` computed from a cryptographic agreement scheme.
    fn derive(compiler: &mut J, secret: Self::Key) -> Self::Output;
}

/// Key Agreement Scheme
///
/// # Specification
///
/// All implementations of this trait must adhere to the following properties:
///
/// 1. **Agreement**: For all possible inputs, the following function returns `true`:
///
///     ```text
///     fn agreement(lhs: SecretKey, rhs: SecretKey) -> bool {
///         agree(lhs, derive(rhs)) == agree(rhs, derive(lhs))
///     }
///     ```
///     This ensures that both parties in the shared computation will arrive at the same conclusion
///     about the value of the [`SharedSecret`](Self::SharedSecret).
pub trait KeyAgreementScheme<J = ()> {
    /// Secret Key Type
    type SecretKey;

    /// Public Key Type
    type PublicKey;

    /// Shared Secret Type
    type SharedSecret;

    /// Derives a public key corresponding to `secret_key`. This public key should be sent to the
    /// other party involved in the shared computation.
    fn derive(compiler: &mut J, secret_key: &Self::SecretKey) -> Self::PublicKey;

    /// Derives a public key corresponding to `secret_key`. This public key should be sent to the
    /// other party involved in the shared computation.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`derive`] when the `secret_key` value is owned,
    /// and by default, [`derive`] is used as its implementation. This method must return the same
    /// value as [`derive`] on the same input.
    ///
    /// [`derive`]: Self::derive
    #[inline]
    fn derive_owned(compiler: &mut J, secret_key: Self::SecretKey) -> Self::PublicKey {
        Self::derive(compiler, &secret_key)
    }

    /// Computes the shared secret given the known `secret_key` and the given `public_key`.
    fn agree(
        compiler: &mut J,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
    ) -> Self::SharedSecret;

    /// Computes the shared secret given the known `secret_key` and the given `public_key`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`agree`] when the `secret_key` value and
    /// `public_key` value are owned, and by default, [`agree`] is used as its implementation. This
    /// method must return the same value as [`agree`] on the same input.
    ///
    /// [`agree`]: Self::agree
    #[inline]
    fn agree_owned(
        compiler: &mut J,
        secret_key: Self::SecretKey,
        public_key: Self::PublicKey,
    ) -> Self::SharedSecret {
        Self::agree(compiler, &secret_key, &public_key)
    }
}
