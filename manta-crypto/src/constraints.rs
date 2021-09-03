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
