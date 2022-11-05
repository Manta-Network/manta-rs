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

//! Poseidon Configuration

use crate::{config::ConstraintField, crypto::poseidon};
use manta_crypto::eclair::alloc::Constant;

/// Poseidon Specification Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Spec<const ARITY: usize>;

impl poseidon::Constants for Spec<2> {
    const WIDTH: usize = 3;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 55;
}

impl poseidon::Constants for Spec<3> {
    const WIDTH: usize = 4;
    const FULL_ROUNDS: usize = 8; // FIXME
    const PARTIAL_ROUNDS: usize = 55; // FIXME
}

impl poseidon::Constants for Spec<4> {
    const WIDTH: usize = 5;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 56;
}

impl poseidon::Constants for Spec<5> {
    const WIDTH: usize = 6;
    const FULL_ROUNDS: usize = 8; // FIXME:
    const PARTIAL_ROUNDS: usize = 56; // FIXME
}

impl<const ARITY: usize> poseidon::arkworks::Specification for Spec<ARITY>
where
    Self: poseidon::Constants,
{
    type Field = ConstraintField;

    const SBOX_EXPONENT: u64 = 5;
}

impl<const ARITY: usize, COM> Constant<COM> for Spec<ARITY> {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

///
pub type Spec2 = Spec<2>;

///
pub type Spec3 = Spec<3>;

///
pub type Spec4 = Spec<4>;

///
pub type Spec5 = Spec<5>;


///
#[cfg(test)]
pub mod test {
    use manta_crypto::{rand::{OsRng, Sample}, permutation::PseudorandomPermutation, encryption::{Encrypt, Decrypt}};
    use manta_util::{BoxArray, rayon::vec};

    use crate::{crypto::poseidon::{Permutation, State, Constants, encryption::{FixedDuplexer, BlockArray, PlaintextBlock}}, config::{ConstraintField}};
    use alloc::boxed::Box;
    use crate::crypto::constraint::arkworks::Fp;

    use super::{Spec4, Spec};

    #[test]
    fn poseidon_permutation_is_correct() {
        let mut rng = OsRng;
        let permutation = Permutation::<Spec4>::gen(&mut rng);
        let field_elements = <[Fp<ConstraintField>; Spec4::WIDTH]>::gen(&mut rng);
        let mut state = State::new(Box::new(field_elements));
        println!("I made it here");
        let result = permutation.permute(&mut state, &mut ());
        println!("And here");
        println!("{result:?}");
    }

    #[test]
    fn poseidon_duplexer_is_wrong() {
        // it seems the tags computed with our duplexer construction are wrong.
        const N: usize = 3;
        let mut rng = OsRng;
        let duplexer = FixedDuplexer::<1, Spec<N>>::gen(&mut rng);
        let field_elements = <[Fp<ConstraintField>; Spec::<N>::WIDTH-1]>::gen(&mut rng);
        let plaintext_block = PlaintextBlock(Box::new(field_elements));
        let plaintext = BlockArray::<_,1>([plaintext_block].into());
        let mut key = Vec::new();
        let key_element_1 = Fp::<ConstraintField>::gen(&mut rng);
        let key_element_2 = Fp::<ConstraintField>::gen(&mut rng);
        key.push(key_element_1);
        key.push(key_element_2);
        let randomness = ();
        let header = vec![];
        let ciphertext = duplexer.encrypt(&key, &randomness, &header, &plaintext, &mut ());
        let (tag,decrypted_plaintext) = duplexer.duplex_decryption(&key, &header, &ciphertext.message, &mut ());
        assert_eq!(plaintext, decrypted_plaintext);
        assert_eq!(ciphertext.tag, tag, "\nThe tags are not equal! Big problems with the duplexer!");
    }
}
