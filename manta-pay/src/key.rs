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

//! Secret Key Generation
//!
//! This module contains [`KeySecret`] which implements a hierarchical deterministic key generation
//! scheme based on the [`BIP-0044`] specification. We may implement other kinds of key generation
//! schemes in the future.
//!
//! See [`CoinType`] for the coins which this key generation scheme can control.
//!
//! [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

use alloc::{format, string::String, vec::Vec};
use core::{
    hash::{Hash, Hasher},
    marker::PhantomData,
};
use manta_accounting::key::{self, AccountIndex};
use manta_crypto::rand::{CryptoRng, RngCore};
use manta_util::{create_seal, seal, Array};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize, Serializer};

pub use bip0039::{self, Error};
pub use bip32::{self, XPrv as SecretKey};

create_seal! {}

/// Coin Type Id Type
pub type CoinTypeId = u128;

/// Coin Type Marker Trait
///
/// This trait identifies a coin type and its identifier for the [`BIP-0044`] specification. This
/// trait is sealed and can only be used with the existing implementations.
///
/// [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
pub trait CoinType: sealed::Sealed {
    /// The coin type id for this coin.
    ///
    /// See [`SLIP-0044`] for a list of registered coin type ids.
    ///
    /// [`SLIP-0044`]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    const COIN_TYPE_ID: CoinTypeId;
}

/// Implements the [`CoinType`] trait for `$coin` with coin type id given by `$id`.
macro_rules! impl_coin_type {
    (
        $coin:ident,
        $doc:expr,
        $name:expr,
        $id:expr,
        $coin_type_id:ident,
        $key_secret:ident,
        $account_map:ident
    ) => {
        #[doc = $doc]
        #[doc = "Network"]
        #[doc = $name]
        #[doc = "Coin Type"]
        pub struct $coin;

        #[doc = stringify!($coin)]
        #[doc = "Coin Type Id"]
        pub const $coin_type_id: CoinTypeId = $id;

        #[doc = stringify!($coin)]
        #[doc = "[`KeySecret`] Type"]
        pub type $key_secret = KeySecret<$coin>;

        #[doc = stringify!($coin)]
        #[doc = "[`VecAccountMap`] Type"]
        pub type $account_map = VecAccountMap<$coin>;

        seal!($coin);

        impl CoinType for $coin {
            const COIN_TYPE_ID: CoinTypeId = $coin_type_id;
        }
    };
}

impl_coin_type!(
    Testnet,
    "Test",
    "`testnet`",
    1,
    TESTNET_COIN_TYPE_ID,
    TestnetKeySecret,
    TestnetAccountMap
);

impl_coin_type!(
    Manta,
    "Main",
    "`manta`",
    611,
    MANTA_COIN_TYPE_ID,
    MantaKeySecret,
    MantaAccountMap
);

impl_coin_type!(
    Calamari,
    "Canary",
    "`calamari`",
    612,
    CALAMARI_COIN_TYPE_ID,
    CalamariKeySecret,
    CalamariAccountMap
);

/// Seed Byte Array Type
type SeedBytes = Array<u8, { bip32::Seed::SIZE }>;

/// Key Secret
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""), Debug, Eq, Hash, PartialEq)]
pub struct KeySecret<C>
where
    C: CoinType,
{
    /// Key Seed
    seed: SeedBytes,

    /// Mnemonic
    mnemonic: Mnemonic,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C> KeySecret<C>
where
    C: CoinType,
{
    /// Builds a [`KeySecret`] from `seed` and `mnemonic`.
    #[inline]
    fn new_unchecked(seed: [u8; bip32::Seed::SIZE], mnemonic: Mnemonic) -> Self {
        Self {
            seed: seed.into(),
            mnemonic,
            __: PhantomData,
        }
    }

    /// Converts a `mnemonic` phrase into a [`KeySecret`], locking it with `password`.
    #[inline]
    #[must_use]
    pub fn new(mnemonic: Mnemonic, password: &str) -> Self {
        Self::new_unchecked(mnemonic.to_seed(password), mnemonic)
    }

    /// Exposes a shared reference to the [`Mnemonic`] for `self`.
    #[inline]
    pub fn expose_mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    /// Samples a random [`KeySecret`] from `rng` with no password.
    #[inline]
    pub fn sample<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::new(Mnemonic::sample(rng), "")
    }

    /// Returns the [`SecretKey`].
    #[inline]
    pub fn xpr_secret_key(&self, index: &AccountIndex) -> SecretKey {
        SecretKey::derive_from_path(
            self.seed,
            &path_string::<C>(*index)
                .parse()
                .expect("Path string is valid by construction."),
        )
        .expect("Unable to generate secret key for valid seed and path string.")
    }
}

/// Account type
pub type Account<C = Manta> = key::Account<KeySecret<C>>;

/// Vec Account type
pub type VecAccountMap<C> = Vec<Account<C>>;

/// Computes the [`BIP-0044`] path string for the given coin settings.
///
/// [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[inline]
#[must_use]
pub fn path_string<C>(account: AccountIndex) -> String
where
    C: CoinType,
{
    const BIP_44_PURPOSE_ID: u8 = 44;
    format!(
        "m/{}'/{}'/{}'",
        BIP_44_PURPOSE_ID,
        C::COIN_TYPE_ID,
        account.index()
    )
}

/// Mnemonic
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields, try_from = "String")
)]
#[derive(Clone, Debug)]
pub struct Mnemonic(
    /// Underlying BIP39 Mnemonic
    #[cfg_attr(feature = "serde", serde(serialize_with = "Mnemonic::serialize"))]
    bip0039::Mnemonic,
);

impl Mnemonic {
    /// Create a new BIP0039 mnemonic phrase from the given string.
    #[inline]
    pub fn new(phrase: &str) -> Result<Self, Error> {
        bip0039::Mnemonic::from_phrase(phrase).map(Self)
    }

    /// Samples a random 12 word [`Mnemonic`] using the entropy returned from `rng`.
    #[inline]
    pub fn sample<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut entropy: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut entropy);
        Self(
            bip0039::Mnemonic::from_entropy(entropy.to_vec())
                .expect("Creating a Mnemonic from 16 bytes of entropy is not allowed to fail."),
        )
    }

    /// Convert this mnemonic phrase into the BIP32 seed value.
    #[inline]
    pub fn to_seed(&self, password: &str) -> [u8; bip32::Seed::SIZE] {
        self.0.to_seed(password)
    }

    /// Serializes the underlying `mnemonic` phrase.
    #[cfg(feature = "serde")]
    #[inline]
    fn serialize<S>(mnemonic: &bip0039::Mnemonic, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        mnemonic.phrase().serialize(serializer)
    }
}

impl AsRef<str> for Mnemonic {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.phrase()
    }
}

impl Eq for Mnemonic {}

impl PartialEq for Mnemonic {
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.as_ref().eq(rhs.as_ref())
    }
}

impl Hash for Mnemonic {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state)
    }
}

impl TryFrom<String> for Mnemonic {
    type Error = Error;

    #[inline]
    fn try_from(string: String) -> Result<Self, Self::Error> {
        Self::new(string.as_str())
    }
}

/// Testing framework
#[cfg(test)]
pub mod test {
    use crate::key::{Calamari, CoinType, KeySecret, Manta, Testnet};
    use manta_crypto::rand::{ChaCha12Rng, SeedableRng};

    /// Hardcoded testnet secret key value in bytes for the BIP32 0.3.0 version
    const SECRET_KEY_TESTNET: [u8; 32] = [
        55, 177, 88, 96, 186, 231, 197, 20, 152, 186, 220, 249, 99, 7, 206, 216, 161, 49, 179, 32,
        62, 26, 87, 161, 13, 69, 41, 84, 20, 146, 126, 20,
    ];

    /// Hardcoded manta secret key value in bytes for the BIP32 0.3.0 version
    const SECRET_KEY_MANTA: [u8; 32] = [
        228, 135, 94, 228, 192, 30, 201, 41, 57, 204, 21, 73, 71, 4, 79, 69, 6, 223, 159, 72, 196,
        237, 14, 159, 211, 248, 36, 248, 128, 71, 142, 251,
    ];

    /// Hardcoded calamari secret key value in bytes for the BIP32 0.3.0 version
    const SECRET_KEY_CALAMARI: [u8; 32] = [
        170, 5, 152, 195, 158, 157, 166, 172, 135, 10, 191, 238, 53, 71, 37, 124, 103, 223, 17,
        194, 178, 237, 231, 204, 21, 14, 23, 174, 90, 248, 129, 208,
    ];

    /// Computes a secret key and asserts it is equal to the hardcoded `value`.
    #[inline]
    pub fn secret_key_generation<C>(value: [u8; 32])
    where
        C: CoinType,
    {
        let mut rng = ChaCha12Rng::from_seed([0u8; 32]);
        let xpr_secret_key = KeySecret::<C>::sample(&mut rng)
            .xpr_secret_key(&Default::default())
            .to_bytes();
        assert_eq!(
            xpr_secret_key, value,
            "BIP32 version is not backward-compatible with 0.3.0."
        );
    }

    /// Runs the test above for [`Testnet`], [`Manta`] and [`Calamari`].
    #[test]
    fn secret_key_generation_test() {
        secret_key_generation::<Testnet>(SECRET_KEY_TESTNET);
        secret_key_generation::<Manta>(SECRET_KEY_MANTA);
        secret_key_generation::<Calamari>(SECRET_KEY_CALAMARI);
    }
}
