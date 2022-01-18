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

//! Secret Key Generation
//!
//! This module contains [`KeySecret`] which implements a hierarchical deterministic key generation
//! scheme based on the [`BIP-0044`] specification. We may implement other kinds of key generation
//! schemes in the future.
//!
//! See [`CoinType`] for the coins which this key generation scheme can control.
//!
//! [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

use alloc::{format, string::String};
use bip32::{Seed, XPrv};
use core::marker::PhantomData;
use manta_accounting::key::{
    self, AccountIndex, HierarchicalKeyDerivationScheme, SpendIndex, ViewIndex,
};
use manta_crypto::rand::{CryptoRng, RngCore, Sample, Standard};
use manta_util::{create_seal, seal};

pub use bip32::{Error, Language, Mnemonic};

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
        $account_table:ident
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
        #[doc = "[`AccountTable`] Type"]
        pub type $account_table = AccountTable<$coin>;

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
    TestnetAccountTable
);

impl_coin_type!(
    Manta,
    "Main",
    "`manta`",
    611,
    MANTA_COIN_TYPE_ID,
    MantaKeySecret,
    MantaAccountTable
);

impl_coin_type!(
    Calamari,
    "Canary",
    "`calamari`",
    612,
    CALAMARI_COIN_TYPE_ID,
    CalamariKeySecret,
    CalamariAccountTable
);

/// Account Table Type
pub type AccountTable<C> = key::AccountTable<KeySecret<C>>;

/// Key Secret
pub struct KeySecret<C>
where
    C: CoinType,
{
    /// Key Seed
    seed: Seed,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C> KeySecret<C>
where
    C: CoinType,
{
    /// Builds a [`KeySecret`] from a raw `seed`.
    #[inline]
    fn from_seed(seed: Seed) -> Self {
        Self {
            seed,
            __: PhantomData,
        }
    }

    /// Converts a `mnemonic` phrase into a [`KeySecret`], locking it with `password`.
    #[inline]
    #[must_use]
    pub fn new(mnemonic: Mnemonic, password: &str) -> Self {
        Self::from_seed(mnemonic.to_seed(password))
    }
}

impl<C> Sample for KeySecret<C>
where
    C: CoinType,
{
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        let mut seed = [0; Seed::SIZE];
        rng.fill_bytes(&mut seed);
        Self::from_seed(Seed::new(seed))
    }
}

/// Computes the [`BIP-0044`] path string for the given coin settings.
///
/// [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[inline]
#[must_use]
pub fn path_string<C>(account: AccountIndex, spend: SpendIndex, view: Option<ViewIndex>) -> String
where
    C: CoinType,
{
    const BIP_44_PURPOSE_ID: u8 = 44;
    format!(
        "m/{}'/{}'/{}'/{}'/{}'",
        BIP_44_PURPOSE_ID,
        C::COIN_TYPE_ID,
        account.index(),
        spend.index(),
        view.map(move |v| v.index() + 1).unwrap_or_default(),
    )
}

impl<C> HierarchicalKeyDerivationScheme for KeySecret<C>
where
    C: CoinType,
{
    type SecretKey = XPrv;
    type Error = Error;

    #[inline]
    fn derive(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: Option<ViewIndex>,
    ) -> Result<Self::SecretKey, Self::Error> {
        XPrv::derive_from_path(&self.seed, &path_string::<C>(account, spend, view).parse()?)
    }
}
