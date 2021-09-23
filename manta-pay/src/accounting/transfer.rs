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

//! Transfer Implementations

use crate::accounting::config::Configuration;
use manta_accounting::transfer::{self, canonical};

/// Mint Transaction Type
pub type Mint = canonical::Mint<Configuration>;

/// Private Transfer Transaction Type
pub type PrivateTransfer = canonical::PrivateTransfer<Configuration>;

/// Reclaim Transaction Type
pub type Reclaim = canonical::Reclaim<Configuration>;

/// Transfer Post Type
pub type TransferPost = transfer::TransferPost<Configuration>;
