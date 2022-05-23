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

//! LFSR implementation.
// adapted from: https://github.com/arkworks-rs/sponge/blob/51d6fc9aac1fa69f44a04839202b5de828584ed8/src/poseidon/grain_lfsr.rs

use crate::crypto::hash::poseidon::FieldGeneration;
use alloc::vec::Vec;

const LFSR_SIZE: usize = 80;

/// An 80-bit linear feedback shift register, described in
/// [GKRRS19](https://eprint.iacr.org/2019/458.pdf) Appendix A. `GrainLFSR`
/// is used to generate secure parameter for Poseidon Hash.
pub struct GrainLFSR {
    state: [bool; LFSR_SIZE],
    prime_num_bits: u64,
    head: usize,
}

fn append_bits<T>(state: &mut [bool; LFSR_SIZE], head: &mut usize, n: usize, from: T)
where
    T: Into<u128>,
{
    let val = from.into() as u128;
    for i in (0..n).rev() {
        state[*head] = (val >> i) & 1 != 0;
        *head += 1;
        *head %= LFSR_SIZE;
    }
}

impl GrainLFSR {
    /// Return a new `GrainLFSR` for poseidon parameter generation.
    pub fn new(
        prime_num_bits: u64,
        width: usize,
        num_full_rounds: usize,
        num_partial_rounds: usize,
    ) -> Self {
        let mut init_sequence = [false; LFSR_SIZE];
        let mut head = 0;
        // b0, b1 describes the field
        append_bits(&mut init_sequence, &mut head, 2, 1u8);
        // b2...=b5 describes s-box: we always use non-inverse s-box
        append_bits(&mut init_sequence, &mut head, 4, 0b00000u8);
        // b6...=b17 describes prime_num_bits
        append_bits(&mut init_sequence, &mut head, 12, prime_num_bits);
        // b18...=b29 describes width
        append_bits(&mut init_sequence, &mut head, 12, width as u16);
        // b30..=39 describes num_full_rounds
        append_bits(&mut init_sequence, &mut head, 10, num_full_rounds as u16);
        // b40..=49 describes num_partial_rounds
        append_bits(&mut init_sequence, &mut head, 10, num_partial_rounds as u16);
        // b50..=79 describes the constant 1
        append_bits(
            &mut init_sequence,
            &mut head,
            30,
            0b111111111111111111111111111111u128,
        );
        let mut res = Self {
            state: init_sequence,
            prime_num_bits,
            head,
        };
        res.init();
        res
    }

    /// Updates 1 bit at `self.state[self.head]` and increases `self.head` by 1.
    fn update(&mut self) -> bool {
        let new_bit =
            self.bit(62) ^ self.bit(51) ^ self.bit(38) ^ self.bit(23) ^ self.bit(13) ^ self.bit(0);
        self.state[self.head] = new_bit;
        self.head += 1;
        self.head %= LFSR_SIZE;
        new_bit
    }

    /// Initializes LFSR in terms of `self.state` and `self.head`.
    fn init(&mut self) {
        for _ in 0..LFSR_SIZE * 2 {
            self.update();
        }
    }

    /// Returns the bit value of `self.state` at the position `index + self.head`.
    #[inline]
    fn bit(&self, index: usize) -> bool {
        self.state[(index + self.head) % LFSR_SIZE]
    }

    /// Gets `num_bits` bits, represent each bit as a bool, and return a vector of bools.
    pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut res = Vec::new();
        for _ in 0..num_bits {
            // Obtains the first bit
            let mut new_bit = self.update();
            // Loop until the first bit is true
            while !new_bit {
                // Discards the second bit
                let _ = self.update();
                // Obtains another first bit
                new_bit = self.update();
            }
            // Obtains the second bit
            res.push(self.update());
        }
        res
    }

    /// Performs rejection sampling until the sampled bits can construct a valid field element.
    fn sample_element<F>(&mut self) -> F
    where
        F: FieldGeneration,
    {
        loop {
            let mut bits = self.get_bits(self.prime_num_bits as usize);
            bits.reverse();
            if let Some(f) = F::try_from_bits_le(&bits) {
                return f;
            }
        }
    }

    /// Performs rejection sampling until generating `num_elems` field elements.
    pub fn get_field_elements_rejection_sampling<F>(&mut self, num_elems: usize) -> Vec<F>
    where
        F: FieldGeneration,
    {
        assert_eq!(F::MODULUS_BITS as u64, self.prime_num_bits);
        let mut res = Vec::new();
        for _ in 0..num_elems {
            res.push(self.sample_element());
        }
        res
    }
}

#[cfg(test)]
mod test {
    use super::GrainLFSR;
    use crate::crypto::constraint::arkworks::Fp;
    use ark_bls12_381::Fr;
    use ark_ff::field_new;

    #[test]
    fn grain_lfsr_consistency() {
        // sage generate_parameters_grain_deterministic.sage 1 0 255 3 8 55 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
        // This sage script can be found at https://github.com/Manta-Network/Plonk-Prototype/tree/poseidon_hash_clean.
        // TODO: Move sage scripts to Manta-rs repo.
        let mut lfsr = GrainLFSR::new(255, 3, 8, 55);
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fp<_>>(1)[0],
            Fp(field_new!(
                Fr,
                "41764196652518280402801918994067134807238124178723763855975902025540297174931"
            ))
        );
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fp<_>>(1)[0],
            Fp(field_new!(
                Fr,
                "12678502092746318913289523392430826887011664085277767208266352862540971998250"
            ))
        );
    }
}
