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

//! Constraint Systems and Zero Knowledge Proofs

use core::borrow::Borrow;

///
pub trait Register<T>: ProofSystem {
    ///
    type Output;

    ///
    fn allocate<B, Opt>(&mut self, t: Opt) -> Self::Output
    where
        B: Borrow<T>,
        Opt: Into<Option<B>>;

    ///
    #[inline]
    fn variable(&mut self) -> Self::Output {
        Register::allocate::<T, _>(self, None)
    }
}

///
pub trait ProofSystem: Default {
    ///
    type Variable;

    ///
    type Proof;

    ///
    type Error;

    ///
    #[inline]
    fn allocate<T, B>(&mut self, t: impl Into<Option<B>>) -> <Self as Register<T>>::Output
    where
        B: Borrow<T>,
        Self: Register<T>,
    {
        Register::allocate(self, t)
    }

    ///
    fn assert(&mut self, b: ());

    ///
    #[inline]
    fn assert_all<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = ()>,
    {
        for boolean in iter {
            self.assert(boolean)
        }
    }

    ///
    #[inline]
    fn assert_eq(&mut self, lhs: &Self::Variable, rhs: &Self::Variable) {
        // TODO: self.assert(lhs.eq(rhs))
        let _ = (lhs, rhs);
        todo!()
    }

    ///
    #[inline]
    fn assert_all_eq<'i, I>(&mut self, iter: I)
    where
        Self::Variable: 'i,
        I: IntoIterator<Item = &'i Self::Variable>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            for item in iter {
                self.assert_eq(base, item);
            }
        }
    }
}

///
pub trait ProofBuilder {
    ///
    fn build<P>(&self, proof_system: &mut P)
    where
        P: ProofSystem;
}

/* TODO:
use alloc::vec::Vec;

///
pub enum Variable<T = usize> {
    ///
    Input(T),

    ///
    Witness(T),
}

///
pub trait Constraint<T> {
    ///
    fn is_satisfied<C>(&self, cs: &C) -> Option<bool>
    where
        C: ConstraintSystem<T>;
}

///
pub trait ConstraintSystem<T> {
    ///
    type Constraint: Constraint<T>;

    ///
    fn new(shape: bool) -> Self;

    ///
    fn new_input<F>(&mut self, f: F) -> Variable
    where
        F: FnOnce() -> T;

    ///
    fn new_witness<F>(&mut self, f: F) -> Variable
    where
        F: FnOnce() -> T;

    ///
    fn new_variable<F>(&mut self, f: F) -> Variable
    where
        F: FnOnce() -> Variable<T>;

    ///
    fn value(&self, variable: Variable) -> Option<T>;

    ///
    fn add(&mut self, constraint: Self::Constraint);

    ///
    fn input_count(&self) -> usize;

    ///
    fn witness_count(&self) -> usize;

    ///
    #[inline]
    fn variable_count(&self) -> usize {
        self.input_count() + self.witness_count()
    }

    ///
    fn constraint_count(&self) -> usize;

    ///
    fn is_satisfied(&self) -> Option<bool>;
}

///
pub trait ConstraintSynthesizer<T> {
    ///
    fn synthesize<C>(&self, cs: &mut C)
    where
        C: ConstraintSystem<T>;

    ///
    fn input(&self) -> Vec<&T>;
}
*/
