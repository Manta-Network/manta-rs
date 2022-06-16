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

//! Poseidon implementation of sponge

use alloc::vec::Vec;
use manta_crypto::permutation::{
    sponge::{Absorb, Mask, Squeeze},
    PseudorandomPermutation,
};

type Domain<S, COM, const ARITY: usize> =
    <super::Hasher<S, ARITY, COM> as PseudorandomPermutation<COM>>::Domain;

impl<S, const ARITY: usize, COM> Absorb<super::Hasher<S, ARITY, COM>, COM> for Vec<S::Field>
where
    S: super::Specification<COM>,
{
    fn write(&self, state: &mut Domain<S, COM, ARITY>, compiler: &mut COM) {
        assert_eq!(self.len(), ARITY);
        // corresponds to algorithm 2 in page 7 of BDPA11, replacing XOR with ADD
        state.iter_mut().zip(self.iter()).for_each(|(s, c)| {
            S::add_assign(s, c, compiler);
        });
    }
}

impl<S, const ARITY: usize, COM> Squeeze<super::Hasher<S, ARITY, COM>, COM> for Vec<S::Field>
where
    S: super::Specification<COM>,
    S::Field: Clone,
{
    #[inline]
    fn read(state: &Domain<S, COM, ARITY>, compiler: &mut COM) -> Self {
        let _ = compiler;
        assert_eq!(
            state.len(),
            ARITY + 1,
            "expect state to be of length ARITY + 1, got {}",
            state.len()
        );
        state.iter().take(ARITY).cloned().collect()
    }
}

impl<S, const ARITY: usize, COM> Mask<super::Hasher<S, ARITY, COM>, Self, Self, COM>
    for Vec<S::Field>
where
    S: super::Specification<COM>,

    S::Field: Clone,
{
    #[inline]
    fn mask(&self, mask: &Self, compiler: &mut COM) -> Self {
        assert_eq!(
            self.len(),
            ARITY,
            "expect state to be of length ARITY, got {}",
            self.len()
        );
        assert_eq!(
            mask.len(),
            ARITY,
            "expect mask to be of length ARITY, got {}",
            mask.len()
        );
        self.iter()
            .zip(mask.iter())
            .map(|(s, m)| S::add(s, m, compiler))
            .collect()
    }

    #[inline]
    fn unmask(masked: &Self, mask: &Self, compiler: &mut COM) -> Self {
        assert_eq!(
            masked.len(),
            ARITY,
            "expect state to be of length ARITY, got {}",
            masked.len()
        );
        assert_eq!(
            mask.len(),
            ARITY,
            "expect mask to be of length ARITY, got {}",
            mask.len()
        );
        masked
            .iter()
            .zip(mask.iter())
            .map(|(s, m)| S::sub(s, m, compiler))
            .collect()
    }
}

#[cfg(test)]
#[cfg(feature = "arkworks")]
mod tests {
    use crate::crypto::{constraint::arkworks::Fp, hash::poseidon::arkworks::Specification};
    use ark_ff::field_new;
    use manta_crypto::permutation::{
        duplex::{Configuration, Duplexer},
        PseudorandomPermutation,
    };
    use rand_chacha::ChaChaRng;

    type Fr = ark_bls12_381::Fr;

    struct TestSpec;
    impl Specification for TestSpec {
        type Field = Fr;
        const FULL_ROUNDS: usize = 8;
        const PARTIAL_ROUNDS: usize = 57;
        const SBOX_EXPONENT: u64 = 5;
    }

    type Permutation = crate::crypto::hash::poseidon::Hasher<TestSpec, 2>;

    struct TestDuplexConfig;
    impl Configuration<Permutation> for TestDuplexConfig {
        type Key = ();
        type Header = ();
        type Input = Vec<Fp<Fr>>;
        type Output = Vec<Fp<Fr>>;
        type Mask = Vec<Fp<Fr>>;
        type Tag = ();
        type Verification = ();

        fn initialize(&self, _: &mut ()) -> <Permutation as PseudorandomPermutation>::Domain {
            vec![
                Fp(field_new!(Fr, "1")),
                Fp(field_new!(Fr, "2")),
                Fp(field_new!(Fr, "3")),
            ]
        }

        fn generate_starting_blocks(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            compiler: &mut (),
        ) -> Vec<Self::Input> {
            let _ = (key, header, compiler);
            // return some arbitrary starting state
            vec![
                vec![Fp(field_new!(Fr, "4")), Fp(field_new!(Fr, "5"))],
                vec![Fp(field_new!(Fr, "7")), Fp(field_new!(Fr, "8"))],
            ]
        }

        fn as_tag(
            &self,
            _state: &<Permutation as PseudorandomPermutation>::Domain,
            _compiler: &mut (),
        ) -> Self::Tag {
            unimplemented!("not needed for this test")
        }

        fn verify(
            &self,
            _encryption_tag: &Self::Tag,
            _decryption_tag: &Self::Tag,
            _compiler: &mut (),
        ) -> Self::Verification {
            unimplemented!("not needed for this test")
        }
    }

    #[test]
    fn encryption_consistency() {
        use manta_crypto::rand::*;
        let mut rng = ChaChaRng::seed_from_u64(0);
        let permutation = rng.gen();
        let duplex = Duplexer::new(permutation, TestDuplexConfig);

        let plaintext = (0..7)
            .map(|_| (0..2).map(|_| rng.gen()).collect())
            .collect::<Vec<_>>();
        let (_, ciphertext) = duplex.duplex_encryption(&(), &(), &plaintext, &mut ());
        let (_, decrypted) = duplex.duplex_decryption(&(), &(), &ciphertext, &mut ());

        assert_eq!(plaintext, decrypted);
    }
}
