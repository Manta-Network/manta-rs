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

//! Constraint Proof Systems

// TODO:  Add derive trait to implement `Alloc` for structs (and enums?).
// FIXME: When running functions from `AssertEqual` the compiler requests the type
//        instead of being able to infer it.

/// Variable Type
pub type Variable<P, T> = <T as Alloc<P>>::Output;

/// Boolean Variable Type
pub type Bool<P> = Variable<P, bool>;

/// Byte Variable Type
pub type U8<P> = Variable<P, u8>;

/// Proof System
pub trait ProofSystem: Default {
    /// Proof Type
    type Proof;

    /// Error Type
    type Error;

    /// Returns a proof that the proof system is consistent.
    fn finish(self) -> Result<Self::Proof, Self::Error>;
}

/// Allocation Trait
pub trait Alloc<P>
where
    P: ProofSystem + ?Sized,
{
    /// Resulting Variable Object
    type Output;

    /// Returns a new variable with value `self`.
    fn as_variable(&self, ps: &mut P) -> Self::Output;

    /// Returns a new variable with an unknown value.
    fn unknown(ps: &mut P) -> Self::Output;
}

/// Assertion Trait
pub trait Assert: ProofSystem
where
    bool: Alloc<Self>,
{
    /// Asserts that `b` is `true`.
    fn assert(&mut self, b: Bool<Self>);

    /// Asserts that all the booleans in `iter` are `true`.
    #[inline]
    fn assert_all<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Bool<Self>>,
    {
        iter.into_iter().for_each(move |b| self.assert(b))
    }
}

/// Equality Trait
pub trait Equal<P>: Alloc<P>
where
    P: ProofSystem + ?Sized,
    bool: Alloc<P>,
{
    /// Generates a boolean that represents the fact that `lhs` and `rhs` may be equal.
    fn eq(lhs: &Variable<P, Self>, rhs: &Variable<P, Self>) -> Bool<P>;
}

/// Assert Equal Trait
pub trait AssertEqual<T>: Assert
where
    bool: Alloc<Self>,
    T: Equal<Self>,
{
    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq(&mut self, lhs: &Variable<Self, T>, rhs: &Variable<Self, T>) {
        self.assert(T::eq(lhs, rhs))
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, I>(&mut self, iter: I)
    where
        Variable<Self, T>: 't,
        I: IntoIterator<Item = &'t Variable<Self, T>>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            for item in iter {
                self.assert_eq(base, item);
            }
        }
    }
}
