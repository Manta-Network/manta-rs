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

//! Key Primitives

/// Key-Agreement Scheme
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
pub trait KeyAgreementScheme {
    /// Secret Key Type
    type SecretKey;

    /// Public Key Type
    type PublicKey;

    /// Shared Secret Type
    type SharedSecret;

    /// Derives a public key corresponding to `secret_key`. This public key should be sent to the
    /// other party involved in the shared computation.
    fn derive(secret_key: Self::SecretKey) -> Self::PublicKey;

    /// Computes the shared secret given the known `secret_key` and the given `public_key`.
    fn agree(secret_key: &Self::SecretKey, public_key: &Self::PublicKey) -> Self::SharedSecret;
}

/// Key-Diversification Scheme
///
/// # Specification
///
/// All implementations of this trait must adhere to the following properties:
///
/// 1. **Derivation Invariance**: For all possible inputs, the following function returns `true`:
///
///    ```text
///    fn derivation_invariance(diversifier: SecretKey, lhs: SecretKey, rhs: SecretKey) -> bool {
///        combine_secret_keys(
///            diversifier,
///            KeyAgreementScheme::derive(lhs),
///            KeyAgreementScheme::derive(rhs)
///         ) == combine_public_keys(KeyAgreementScheme::derive(diversifier), lhs, rhs)
///    }
///    ```
pub trait KeyDiversificationScheme {
    /// Secret Key Type
    type SecretKey;

    /// Public Key Type
    type PublicKey;

    /// Key-Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme<
        PublicKey = Self::PublicKey,
        SecretKey = Self::SecretKey,
    >;

    /// Derives a new public key from a given `diversifier` and the `lhs` and `rhs` public keys.
    fn combine_public_keys(
        diversifier: Self::SecretKey,
        lhs: Self::PublicKey,
        rhs: Self::PublicKey,
    ) -> Self::PublicKey;

    /// Derives a new secret key from a given `diversifier` and the `lhs` and `rhs` secret keys.
    fn combine_secret_keys(
        diversifier: Self::PublicKey,
        lhs: Self::SecretKey,
        rhs: Self::SecretKey,
    ) -> Self::SecretKey;
}
