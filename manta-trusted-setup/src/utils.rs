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

//! Groth16 Trusted Setup Utilities

use std::marker::PhantomData;

use manta_util::serde::{Deserialize, Serialize};

/// Store `T` in bytes form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    bound(serialize = r"", deserialize = "",),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct BytesRepr<T> {
    /// The bytes representation of `T`
    pub bytes: Vec<u8>,
    __: PhantomData<T>,
}
