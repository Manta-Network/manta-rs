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

//! Linear Feedback Shift Register

use core::iter::FusedIterator;
use manta_crypto::rand::{Error, RngCore};

// TODO; implement RNG for LFSR

/// An 80-bit linear feedback shift register, described in [GKRRS19] Appendix A.
///
/// [GKRRS19]: https://eprint.iacr.org/2019/458.pdf
///
/// # Note
///
/// This `struct` does not implement `Copy` because it also implements `Iterator` which would lead
/// to confusion when using this type in looping contexts.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LinearFeedbackShiftRegister {
    /// LFSR Internal State
    state: [bool; Self::SIZE],

    /// Head Pointer into [`self.state`](Self::state)
    head: usize,
    // TODO we add a `ptr` and `pad` field here
    /*
     pad is used as a workaround to simulate sampling bits from sampling bytes. We need `pad`
     because when sampling bytes, we require getting 8-bits chunk at a time, but when sampling bits,
     we only get 1-bit at a time. For example, when sampling 15 bits, without padding, the RNG
     will draw 2 bytes (which is 16 bits) from LFSR, the standard one draws only 15 bits. So, the end state will become different.

     Using `pad` makes the end state the same, but padding some dummy bits at the end of last byte, if necessary.

     expected behavior on update:
     - when `ptr < pad`, draw a boolean from LFSR, ptr += 1, output
     - when `pad <= ptr < ((pad + 7) / 8) + 8`, output 0, ptr += 1
     - otherwise, set `ptr = 0`
    */
}

impl LinearFeedbackShiftRegister {
    /// LFSR State Size
    pub const SIZE: usize = 80;

    /// Generates a [`GrainLFSR`] from a
    #[inline]
    pub fn from_seed<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (usize, u128)>,
    {
        let mut lfsr = Self {
            state: [false; Self::SIZE],
            head: 0,
        };
        for (n, bits) in iter {
            lfsr.append_seed_bits(n, bits);
        }
        lfsr.skip_updates(Self::SIZE * 2);
        lfsr
    }

    /// Appends `n` seed bits into the LFSR state.
    #[inline]
    fn append_seed_bits(&mut self, n: usize, bits: u128) {
        for i in (0..n).rev() {
            self.set_next((bits >> i) & 1 != 0);
        }
    }

    /// Performs `n` updates, ignoring their results.
    #[inline]
    fn skip_updates(&mut self, n: usize) {
        for _ in 0..n {
            self.update();
        }
    }

    /// Sets the bit at the current bit pointed to by the head pointer to `next`, moving the head
    /// pointer forward one step.
    #[inline]
    fn set_next(&mut self, next: bool) -> bool {
        self.state[self.head] = next;
        self.head += 1;
        self.head %= Self::SIZE;
        next
    }

    /// Returns the bit value of `self.state` at the position `index + self.head`.
    #[inline]
    fn bit(&self, index: usize) -> bool {
        self.state[(index + self.head) % Self::SIZE]
    }

    /// Updates 1 bit at `self.state[self.head]` and increases `self.head` by 1.
    fn update(&mut self) -> bool {
        self.set_next(
            self.bit(62) ^ self.bit(51) ^ self.bit(38) ^ self.bit(23) ^ self.bit(13) ^ self.bit(0),
        )
    }
}

impl Iterator for LinearFeedbackShiftRegister {
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let mut bit = self.update();
        while !bit {
            self.update();
            bit = self.update();
        }
        Some(self.update())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

impl FusedIterator for LinearFeedbackShiftRegister {}

impl RngCore for LinearFeedbackShiftRegister {
    fn next_u32(&mut self) -> u32 {
        // we use big endian as convention of LFSR.
        // For example, LFSR output [0,1,1,1,0,1,0,1,1,0] first converts to bytes [0b01110101, 0b10]
        // and then to u32 as 0b01110101_10
        let mut repr = [0u8; 4];
        self.fill_bytes(&mut repr);
        u32::from_be_bytes(repr)
    }

    fn next_u64(&mut self) -> u64 {
        let mut repr = [0u8; 8];
        self.fill_bytes(&mut repr);
        u64::from_be_bytes(repr)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.iter_mut().for_each(|byte| {
            let mut result = 0u8;
            // we will each byte with 8 bits in big endian order
            (0..8usize).for_each(|i| {
                // LFSR is an infinite iterator, we can can safely unwrap here
                let bit = self.next().unwrap();
                result |= (bit as u8) << i;
            });
            *byte = result;
        })
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
