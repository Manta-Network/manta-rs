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
use core::{marker::PhantomData, num::ParseIntError, str::FromStr};
use manta_accounting::key::{HierarchicalKeyTable, HierarchicalKeyTableParameter};
use manta_util::{create_seal, seal};

pub use bip32::{Error, Mnemonic};

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

/// Implements the [`CoinType`] trait for `$name` with coin type id given by `$id`.
macro_rules! impl_coin_type {
    ($name:ty, $id:ident) => {
        seal!($name);
        impl CoinType for $name {
            const COIN_TYPE_ID: CoinTypeId = $id;
        }
    };
}

/// Test Network `testnet` Coin Type
pub struct Testnet;

/// Test Network `testnet` Coin Type Id
pub const TESTNET_COIN_TYPE_ID: CoinTypeId = 1;

impl_coin_type!(Testnet, TESTNET_COIN_TYPE_ID);

/// Main Network `manta` Coin Type
pub struct Manta;

/// Main Network `manta` Coin Type Id
pub const MANTA_COIN_TYPE_ID: CoinTypeId = 611;

impl_coin_type!(Manta, MANTA_COIN_TYPE_ID);

/// Canary Network `calamari` Coin Type
pub struct Calamari;

/// Canary Network `calamari` Coin Type Id
pub const CALAMARI_COIN_TYPE_ID: CoinTypeId = 612;

impl_coin_type!(Calamari, CALAMARI_COIN_TYPE_ID);

/// Parse Parameter Error
pub struct ParseParameterError(ParseIntError);

/// Implements some [`From`] traits for `$name`.
macro_rules! impl_from_for_parameter {
    ($name:ty, $($from:ty),+$(,)?) => {
        $(
            impl From<$from> for $name {
                #[inline]
                fn from(t: $from) -> Self {
                    Self(t.into())
                }
            }
        )+
    }
}

/// Implements the [`HierarchicalKeyTableParameter`] trait for `$name`.
macro_rules! impl_parameter {
    ($name:ty) => {
        impl HierarchicalKeyTableParameter for $name {
            #[inline]
            fn increment(&mut self) {
                self.0 += 1;
            }
        }

        impl_from_for_parameter!($name, bool, u8, u16, u32, u64, u128);

        impl FromStr for $name {
            type Err = ParseParameterError;

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(s.parse().map_err(ParseParameterError)?))
            }
        }
    };
}

/// Parameter Type
type ParameterType = u128;

/// Account Parameter
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountParameter(ParameterType);

impl_parameter!(AccountParameter);

/// Index Parameter
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IndexParameter(ParameterType);

impl_parameter!(IndexParameter);

/// Testnet [`KeySecret`] Type
pub type TestnetKeySecret = KeySecret<Testnet>;

/// Manta [`KeySecret`] Type
pub type MantaKeySecret = KeySecret<Manta>;

/// Calamari [`KeySecret`] Type
pub type CalamariKeySecret = KeySecret<Calamari>;

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
    /// Converts a `mnemonic` phrase into a [`KeySecret`], locking it with `password`.
    #[must_use]
    #[inline]
    pub fn new(mnemonic: Mnemonic, password: &str) -> Self {
        Self {
            seed: mnemonic.to_seed(password),
            __: PhantomData,
        }
    }
}

/// Computes the [`BIP-0044`] path string for the given coin settings.
///
/// [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[must_use]
#[inline]
pub fn path_string<C>(account: &AccountParameter, index: &IndexParameter, kind: u32) -> String
where
    C: CoinType,
{
    const BIP_44_PURPOSE_ID: u8 = 44;
    format!(
        "m/{}'/{}'/{}'/{}/{}",
        BIP_44_PURPOSE_ID,
        C::COIN_TYPE_ID,
        account.0,
        kind,
        index.0
    )
}

impl<C> HierarchicalKeyTable for KeySecret<C>
where
    C: CoinType,
{
    type SecretKey = XPrv;

    type Account = AccountParameter;

    type Index = IndexParameter;

    type Kind = u32;

    type Error = Error;

    #[inline]
    fn get(
        &self,
        account: &Self::Account,
        index: &Self::Index,
        kind: &Self::Kind,
    ) -> Result<Self::SecretKey, Self::Error> {
        XPrv::derive_from_path(
            &self.seed,
            &path_string::<C>(account, index, *kind).parse()?,
        )
    }
}
