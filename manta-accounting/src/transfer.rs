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
    asset::{Asset, AssetCollection},
};
use manta_crypto::{IntegratedEncryptionScheme, VerifiedSet};

/// Transfer Configuration Trait
pub trait TransferConfiguration: IdentityConfiguration {
    /// Integrated Encryption Scheme for [`Asset`]
    type IntegratedEncryptionScheme: IntegratedEncryptionScheme<Plaintext = Asset>;

    /// Verified Set for [`Utxo`]
    type UtxoSet: VerifiedSet<Item = Utxo<Self>>;
}

/// Transfer Protocol
pub struct Transfer<
    T,
    const SOURCES: usize,
    const SENDERS: usize,
    const RECEIVERS: usize,
    const SINKS: usize,
> where
    T: TransferConfiguration,
{
    /// Public Asset Sources
    pub sources: AssetCollection<SOURCES>,

    /// Secret Senders
    pub senders: [Sender<T, T::UtxoSet>; SENDERS],

    /// Secret Receivers
    pub receivers: [Receiver<T, T::IntegratedEncryptionScheme>; RECEIVERS],

    /// Public Asset Sinks
    pub sinks: AssetCollection<SINKS>,
}

/// Private Transfer Protocol
pub struct PrivateTransfer<T, const SENDERS: usize, const RECEIVERS: usize>
where
    T: TransferConfiguration,
{
    /// Secret Senders
    pub senders: [Sender<T, T::UtxoSet>; SENDERS],

    /// Secret Receivers
    pub receivers: [Receiver<T, T::IntegratedEncryptionScheme>; RECEIVERS],
}
