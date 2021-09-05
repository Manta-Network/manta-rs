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

//! Transfer Protocols

use crate::{
    account::{IdentityConfiguration, Receiver, Sender, Utxo},
    asset::{sample_asset_balances, Asset, AssetBalances, AssetId},
};
use manta_codec::{ScaleDecode, ScaleEncode};
use manta_crypto::{IntegratedEncryptionScheme, VerifiedSet};
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};

/// Public Transfer Protocol
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ScaleDecode, ScaleEncode)]
pub struct PublicTransfer<const SOURCES: usize, const SINKS: usize> {
    /// Asset Id
    pub asset_id: AssetId,

    /// Public Asset Sources
    pub sources: AssetBalances<SOURCES>,

    /// Public Asset Sinks
    pub sinks: AssetBalances<SINKS>,
}

impl<const SOURCES: usize, const SINKS: usize> PublicTransfer<SOURCES, SINKS> {
    /// Builds a new [`PublicTransfer`].
    pub const fn new(
        asset_id: AssetId,
        sources: AssetBalances<SOURCES>,
        sinks: AssetBalances<SINKS>,
    ) -> Self {
        Self {
            asset_id,
            sources,
            sinks,
        }
    }
}

impl<const SOURCES: usize, const SINKS: usize> Distribution<PublicTransfer<SOURCES, SINKS>>
    for Standard
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> PublicTransfer<SOURCES, SINKS> {
        PublicTransfer::new(
            rng.gen(),
            sample_asset_balances(rng),
            sample_asset_balances(rng),
        )
    }
}

/// Secret Transfer Configuration Trait
pub trait SecretTransferConfiguration: IdentityConfiguration {
    /// Integrated Encryption Scheme for [`Asset`]
    type IntegratedEncryptionScheme: IntegratedEncryptionScheme<Plaintext = Asset>;

    /// Verified Set for [`Utxo`]
    type UtxoSet: VerifiedSet<Item = Utxo<Self>>;
}

/// Secret Transfer Protocol
pub struct SecretTransfer<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: SecretTransferConfiguration,
{
    /// Secret Senders
    pub senders: [Sender<T, T::UtxoSet>; SENDERS],

    /// Secret Receivers
    pub receivers: [Receiver<T, T::IntegratedEncryptionScheme>; RECEIVERS],
}

impl<T, const SENDERS: usize, const RECEIVERS: usize> SecretTransfer<T, SENDERS, RECEIVERS>
where
    T: SecretTransferConfiguration,
{
    /// Builds a new [`SecretTransfer`].
    pub fn new(
        senders: [Sender<T, T::UtxoSet>; SENDERS],
        receivers: [Receiver<T, T::IntegratedEncryptionScheme>; RECEIVERS],
    ) -> Self {
        Self { senders, receivers }
    }
}

/// Transfer Protocol
pub struct Transfer<
    T,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    T: SecretTransferConfiguration,
{
    /// Public Transfer
    pub public: PublicTransfer<SOURCES, SINKS>,

    /// Secret Transfer
    pub secret: SecretTransfer<T, SENDERS, RECEIVERS>,
}
