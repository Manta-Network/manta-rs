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

//! Identity Implementations

use crate::accounting::config::Configuration;
use manta_accounting::{identity, transfer::TransferConfiguration};

/// Asset Parameters
pub type AssetParameters = identity::AssetParameters<Configuration>;

/// Sender Type
pub type Sender =
    identity::Sender<Configuration, <Configuration as TransferConfiguration>::UtxoSet>;

/// Receiver Type
pub type Receiver = identity::Receiver<
    Configuration,
    <Configuration as TransferConfiguration>::IntegratedEncryptionScheme,
>;

/// Shielded Identity Type
pub type ShieldedIdentity = identity::ShieldedIdentity<
    Configuration,
    <Configuration as TransferConfiguration>::IntegratedEncryptionScheme,
>;

/// Spend Type
pub type Spend = identity::Spend<
    Configuration,
    <Configuration as TransferConfiguration>::IntegratedEncryptionScheme,
>;

/// Sender Post Type
pub type SenderPost =
    identity::SenderPost<Configuration, <Configuration as TransferConfiguration>::UtxoSet>;

/// Receiver Post Type
pub type ReceiverPost = identity::ReceiverPost<
    Configuration,
    <Configuration as TransferConfiguration>::IntegratedEncryptionScheme,
>;
