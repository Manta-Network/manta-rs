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

//! LFSH implementation.
// adapted from: https://github.com/arkworks-rs/sponge/blob/51d6fc9aac1fa69f44a04839202b5de828584ed8/src/poseidon/grain_lfsr.rs

use alloc::vec::Vec;

use crate::crypto::hash::poseidon::ParamField;

pub struct GrainLFSR {
    state: [bool; 80],
    prime_num_bits: u64,
    head: usize,
}

fn append_bits<T: Into<u128>>(state: &mut [bool; 80], head: &mut usize, n: usize, from: T) {
    let val = from.into() as u128;
    for i in (0..n).rev() {
        state[*head] = (val >> i) & 1 != 0;
        *head += 1;
        *head %= 80;
    }
}

impl GrainLFSR {
    pub fn new(prime_num_bits: u64, width: usize, r_f: usize, r_p: usize) -> Self {
        let mut init_sequence = [false; 80];
        let mut head = 0;
        // b0, b1 describes the field
        append_bits(&mut init_sequence, &mut head, 2, 1u8);
        // b2...=b5 describes s-box: we always use non-inverse s-box
        append_bits(&mut init_sequence, &mut head, 4, 0b00000u8);
        // b6...=b17 describes prime_num_bits
        append_bits(&mut init_sequence, &mut head, 12, prime_num_bits);
        // b18...=b29 describes width
        append_bits(&mut init_sequence, &mut head, 12, width as u16);
        // b30..=39 describes r_f (num_full_rounds)
        append_bits(&mut init_sequence, &mut head, 10, r_f as u16);
        // b40..=49 describes r_p (num_partial_rounds)
        append_bits(&mut init_sequence, &mut head, 10, r_p as u16);
        // b50..=79 describes the constant 1
        append_bits(
            &mut init_sequence,
            &mut head,
            30,
            0b111111111111111111111111111111u128,
        );
        let mut res = GrainLFSR {
            state: init_sequence,
            prime_num_bits,
            head,
        };
        res.init();
        res
    }

    fn update(&mut self) -> bool {
        let new_bit =
            self.bit(62) ^ self.bit(51) ^ self.bit(38) ^ self.bit(23) ^ self.bit(13) ^ self.bit(0);
        self.state[self.head] = new_bit;
        self.head += 1;
        self.head %= 80;
        new_bit
    }

    fn init(&mut self) {
        for _ in 0..160 {
            self.update();
        }
    }

    #[inline]
    fn bit(&self, index: usize) -> bool {
        self.state[(index + self.head) % 80]
    }

    pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut res = Vec::new();

        for _ in 0..num_bits {
            // Obtain the first bit
            let mut new_bit = self.update();

            // Loop until the first bit is true
            while !new_bit {
                // Discard the second bit
                let _ = self.update();
                // Obtain another first bit
                new_bit = self.update();
            }

            // Obtain the second bit
            res.push(self.update());
        }

        res
    }

    pub fn get_field_elements_rejection_sampling<F>(&mut self, num_elems: usize) -> Vec<F>
    where
        F: ParamField,
    {
        assert_eq!(F::MODULUS_BITS as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Perform rejection sampling
            loop {
                // Obtain n bits and make it most-significant-bit first
                let mut bits = self.get_bits(self.prime_num_bits as usize);
                bits.reverse();

                // Construct the number
                if let Some(f) = F::try_from_bits_le(&bits) {
                    res.push(f);
                    break;
                }
            }
        }

        res
    }

    pub fn get_field_elements_mod_p<F>(&mut self, num_elems: usize) -> Vec<F>
    where
        F: ParamField,
    {
        assert_eq!(F::MODULUS_BITS as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Obtain n bits and make it most-significant-bit first
            let mut bits = self.get_bits(self.prime_num_bits as usize);
            bits.reverse();

            let bytes = bits
                .chunks(8)
                .map(|chunk| {
                    let mut result = 0u8;
                    for (i, bit) in chunk.iter().enumerate() {
                        result |= u8::from(*bit) << i
                    }
                    result
                })
                .collect::<Vec<u8>>();

            res.push(F::from_le_bytes_mod_order(&bytes));
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::GrainLFSR;
    use crate::crypto::constraint::arkworks::Fp;
    use ark_bls12_381::Fr;
    use ark_ff::field_new;

    #[test]
    fn test_grain_lfsr_consistency() {
        // sage generate_parameters_grain_deterministic.sage 1 0 255 3 8 55 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

        let mut lfsr = GrainLFSR::new(255, 3, 8, 55);
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fp<Fr>>(1)[0],
            Fp(field_new!(
                Fr,
                "41764196652518280402801918994067134807238124178723763855975902025540297174931"
            ))
        );
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fp<Fr>>(1)[0],
            Fp(field_new!(
                Fr,
                "12678502092746318913289523392430826887011664085277767208266352862540971998250"
            ))
        );
    }
}
