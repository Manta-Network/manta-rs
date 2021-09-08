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

//! Secret Key Generator Implementations

// TODO: Use the `bip32` crate to implement wallet key generators

/// BIP-0044 Purpose Id
pub const BIP_44_PURPOSE_ID: u32 = 44;

/// Manta Coin Type Id
pub const MANTA_COIN_TYPE_ID: u32 = 611;

/// Calamary Coin Type Id
pub const CALAMARI_COIN_TYPE_ID: u32 = 612;

/// Testnet Coin Type Id
pub const TESTNET_COIN_TYPE_ID: u32 = 1;
