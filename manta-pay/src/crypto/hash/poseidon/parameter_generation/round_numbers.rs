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

//! Generate number of full & partial rounds
//! Adapted from <https://github.com/filecoin-project/neptune/blob/master/src/round_numbers.rs>
//! Only works for BLS12-381!

// The number of bits of the Poseidon prime field modulus. Denoted `n` in the Poseidon paper
// (where `n = ceil(log2(p))`). Note that BLS12-381's scalar field modulus is 255 bits, however we
// use 256 bits for simplicity when operating on bytes as the single bit difference does not affect
// the round number security properties.
const PRIME_BITLEN: usize = 256;

/// Security level (in bits), denoted `M` in the Poseidon paper.
const M: usize = 128;

/// The number of S-boxes (also called the "cost") given by equation (14) in the Poseidon paper:
/// `cost = t * num_full_rounds + num_partial_rounds`.
const fn n_sboxes(t: usize, num_full_rounds: usize, num_partial_rounds: usize) -> usize {
    t * num_full_rounds + num_partial_rounds
}

/// Returns `(num_full_rounds, num_partial_rounds)` for a given `arity`.
pub fn round_numbers_base(arity: usize) -> (usize, usize) {
    let width = arity + 1;
    calc_round_numbers(width, true)
}

/// In case of newly-discovered attacks, we may need stronger security.
/// This option exists so we can preemptively create circuits in order to switch
/// to them quickly if needed.
///
/// "A realistic alternative is to increase the number of partial rounds by 25%.
/// Then it is unlikely that a new attack breaks through this number,
/// but even if this happens then the complexity is almost surely above 2^64, and you will be safe."
/// - D Khovratovich
pub fn round_numbers_strengthened(arity: usize) -> (usize, usize) {
    let (num_full_round, num_partial_rounds) = round_numbers_base(arity);
    // Increase by 25%, rounding up.
    let num_strengthened_partial_rounds = f64::ceil(num_partial_rounds as f64 * 1.25) as usize;
    (num_full_round, num_strengthened_partial_rounds)
}

/// Returns the round numbers for a given `width`. Here, the `security_margin` parameter does not
/// indicate that we are calculating `num_full_rounds` and `num_partial_rounds` for the "strengthened" round numbers, done in
/// the function `round_numbers_strengthened()`.
pub fn calc_round_numbers(width: usize, security_margin: bool) -> (usize, usize) {
    let mut num_full_rounds = 0;
    let mut num_partial_rounds = 0;
    let mut n_sboxes_min = usize::MAX;
    for mut num_full_rounds_test in (2..=1000).step_by(2) {
        for mut num_partial_rounds_test in 4..200 {
            if round_numbers_are_secure(width, num_full_rounds_test, num_partial_rounds_test) {
                if security_margin {
                    num_full_rounds_test += 2;
                    num_partial_rounds_test =
                        (1.075 * num_partial_rounds_test as f32).ceil() as usize;
                }
                let n_sboxes = n_sboxes(width, num_full_rounds_test, num_partial_rounds_test);
                if n_sboxes < n_sboxes_min
                    || (n_sboxes == n_sboxes_min && num_full_rounds_test < num_full_rounds)
                {
                    num_full_rounds = num_full_rounds_test;
                    num_partial_rounds = num_partial_rounds_test;
                    n_sboxes_min = n_sboxes;
                }
            }
        }
    }
    (num_full_rounds, num_partial_rounds)
}

/// Returns `true` if the provided round numbers satisfy the security inequalities specified in the
/// Poseidon paper.
fn round_numbers_are_secure(width: usize, num_full_rounds: usize, num_partial_rounds: usize) -> bool {
    let (num_partial_rounds, width, n, m) = (num_partial_rounds as f32, width as f32, PRIME_BITLEN as f32, M as f32);
    let num_full_rounds_stat = if m <= (n - 3.0) * (width + 1.0) {
        6.0
    } else {
        10.0
    };
    let num_full_rounds_interp = 0.43 * m + width.log2() - num_partial_rounds;
    let num_full_rounds_grob_1 = 0.21 * n - num_partial_rounds;
    let num_full_rounds_grob_2 = (0.14 * n - 1.0 - num_partial_rounds) / (width - 1.0);
    let num_full_rounds_max = [num_full_rounds_stat, num_full_rounds_interp, num_full_rounds_grob_1, num_full_rounds_grob_2]
        .iter()
        .map(|num_full_rounds| num_full_rounds.ceil() as usize)
        .max()
        .unwrap();
        num_full_rounds >= num_full_rounds_max
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{config::PoseidonSpec, crypto::hash::poseidon::hasher::arkworks::Specification};

    #[test]
    fn round_numbers_matches_known_values() {
        // Each case contains a `t` (where `t = arity + 1`) and the `R_P` expected for that `t`.
        let cases = [
            (2usize, 55usize),
            (3, 55),
            (4, 56),
            (5, 56),
            (6, 56),
            (7, 56),
            (8, 57),
            (9, 57),
            (10, 57),
            (11, 57),
            (12, 57),
            (13, 57),
            (14, 57),
            (15, 57),
            (16, 59),
            (17, 59),
            (25, 59),
            (37, 60),
            (65, 61),
        ];
        for (t, rp_expected) in cases.iter() {
            let (rf, rp) = calc_round_numbers(*t, true);
            assert_eq!(rf, 8);
            assert_eq!(rp, *rp_expected);
        }
    }

    fn compare_against_config_values<const ARITY: usize>()
    where
        PoseidonSpec<ARITY>: Specification,
    {
        let (num_full_rounds, num_partial_rounds) = calc_round_numbers(ARITY + 1, true);
        assert_eq!(num_full_rounds, PoseidonSpec::<ARITY>::FULL_ROUNDS);
        assert_eq!(num_partial_rounds, PoseidonSpec::<ARITY>::PARTIAL_ROUNDS);
    }

    #[test]
    fn round_numbers_matches_config_values() {
        compare_against_config_values::<2>();
        compare_against_config_values::<4>();
    }
}
