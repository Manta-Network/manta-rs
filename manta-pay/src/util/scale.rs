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

//! SCALE Utilities

use core::fmt::Debug;
use scale_codec::{Decode, Encode, Input, Output};

#[cfg(feature = "scale-std")]
use {
    scale_codec::IoReader,
    std::io::{Read, Seek, Write},
};

/// Asserts that the SCALE encoding and decoding of `value` is equal to `value`, using `buffer` as
/// the [`Output`] type and `f(buffer)` as the [`Input`].
#[inline]
pub fn assert_valid_codec<'o, T, O, I, F>(value: &T, buffer: &'o mut O, f: F)
where
    T: Debug + Decode + Encode + PartialEq,
    O: Output,
    I: 'o + Input,
    F: FnOnce(&'o mut O) -> I,
{
    value.encode_to(buffer);
    assert_eq!(
        value,
        &T::decode(&mut f(buffer)).expect("Unable to decode the value from the input."),
        "The value and its decoded-encoded form were unequal."
    );
}

/// Asserts that the SCALE encoding and decoding of `value` is equal to `value`, using `buffer` as
/// the [`Output`] and [`Input`] with [`std`].
#[cfg(feature = "scale-std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale-std")))]
#[inline]
pub fn assert_valid_io_codec<T, O>(value: &T, buffer: &mut O)
where
    T: Debug + Decode + Encode + PartialEq,
    O: Read + Seek + Write,
{
    assert_valid_codec(value, buffer, move |b| {
        b.rewind().expect("Unable to rewind buffer.");
        IoReader(b)
    })
}
