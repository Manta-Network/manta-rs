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

//! Manta Pay Signer Tools

use crate::config::Config;
use manta_accounting::wallet::signer;

pub mod client;

#[cfg(feature = "wallet")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "wallet")))]
pub mod base;

/// Synchronization Request
pub type SyncRequest = signer::SyncRequest<Config>;

/// Synchronization Response
pub type SyncResponse = signer::SyncResponse;

/// Synchronization Error
pub type SyncError = signer::SyncError;

/// Sign Response
pub type SignResponse = signer::SignResponse<Config>;

/// Sign Error
pub type SignError = signer::SignError<Config>;

/// Receiving Key Request
pub type ReceivingKeyRequest = signer::ReceivingKeyRequest;
