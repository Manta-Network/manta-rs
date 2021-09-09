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
//! This module contains [`DerivedKeySecret`] which implements the [`BIP-0044`] specification. We
//! may implement other kinds of key generation schemes in the future.
//!
//! See [`CoinType`] for the coins which this key generation scheme can control.
//!
//! [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

use alloc::{format, string::String};
use bip32::Seed;
use core::{marker::PhantomData, num::ParseIntError, str::FromStr};
use manta_accounting::keys::{DerivedSecretKeyGenerator, DerivedSecretKeyParameter};

pub use bip32::{Error, Mnemonic, XPrv as SecretKey};

/// Sealed Trait Module
mod sealed {
    /// Sealed Trait
    pub trait Sealed {}
}

/// Coin Type Id Type
pub type CoinTypeId = u128;

/// Coin Type Marker Trait
///
/// This trait identifies a coin type and its id for the [`BIP-0044`] specification. This trait is
/// sealed and can only be used with the existing implementations.
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
        impl sealed::Sealed for $name {}
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

/// Implements the [`DerivedSecretKeyParameter`] trait for `$name`.
macro_rules! impl_parameter {
    ($name:ty) => {
        impl DerivedSecretKeyParameter for $name {
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
#[derive(Clone, Copy, Default)]
pub struct AccountParameter(ParameterType);

impl_parameter!(AccountParameter);

/// Index Parameter
#[derive(Clone, Copy, Default)]
pub struct IndexParameter(ParameterType);

impl_parameter!(IndexParameter);

/// [`Testnet`] [`DerivedKeySecret`] Alias Type
pub type TestnetDerivedKeySecret = DerivedKeySecret<Testnet>;

/// [`Manta`] [`DerivedKeySecret`] Alias Type
pub type MantaDerivedKeySecret = DerivedKeySecret<Manta>;

/// [`Calamari`] [`DerivedKeySecret`] Alias Type
pub type CalamariDerivedKeySecret = DerivedKeySecret<Calamari>;

/// Derived Key Secret
pub struct DerivedKeySecret<C>
where
    C: CoinType,
{
    /// Derived Key Seed
    seed: Seed,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C> DerivedKeySecret<C>
where
    C: CoinType,
{
    /// Converts a `mnemonic` phrase into a [`DerivedKeySecret`], locking it with `password`.
    #[inline]
    pub fn from_mnemonic(mnemonic: Mnemonic, password: &str) -> Self {
        Self {
            seed: mnemonic.to_seed(password),
            __: PhantomData,
        }
    }
}

/// Computes the [`BIP-0044`] path string for the given coin settings.
///
/// [`BIP-0044`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
pub fn path_string<C>(
    is_external: bool,
    account: &AccountParameter,
    index: &IndexParameter,
) -> String
where
    C: CoinType,
{
    const BIP_44_PURPOSE_ID: u8 = 44;
    format!(
        "m/{}'/{}'/{}'/{}/{}",
        BIP_44_PURPOSE_ID,
        C::COIN_TYPE_ID,
        account.0,
        if is_external { 0 } else { 1 },
        index.0
    )
}

impl<C> DerivedSecretKeyGenerator for DerivedKeySecret<C>
where
    C: CoinType,
{
    type SecretKey = SecretKey;

    type Account = AccountParameter;

    type Index = IndexParameter;

    type Error = Error;

    #[inline]
    fn generate_key(
        &self,
        is_external: bool,
        account: &Self::Account,
        index: &Self::Index,
    ) -> Result<Self::SecretKey, Self::Error> {
        SecretKey::derive_from_path(
            &self.seed,
            &path_string::<C>(is_external, account, index).parse()?,
        )
    }
}
