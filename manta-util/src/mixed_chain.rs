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

//! Mixed Chain Iterator

// TODO:  Make extract its own public trait to see if we can get some more combinators out of this.
// FIXME: Implement `Debug` for `MixedChain`.

use crate::Either;
use core::iter::FusedIterator;

trait Extract<I>
where
    I: Iterator,
{
    fn extract(iter: &mut I) -> Option<I::Item>;
}

struct Next;

impl<I> Extract<I> for Next
where
    I: Iterator,
{
    #[inline]
    fn extract(iter: &mut I) -> Option<I::Item> {
        iter.next()
    }
}

struct NextBack;

impl<I> Extract<I> for NextBack
where
    I: DoubleEndedIterator,
{
    #[inline]
    fn extract(iter: &mut I) -> Option<I::Item> {
        iter.next_back()
    }
}

/// An iterator that links two iterators together, in a chain, mapping each iterator so that they
/// have a common type when chained.
#[derive(Clone)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct MixedChain<A, B, F> {
    // NOTE: See the standard library implementation of `Chain` for an explanation on the
    //       fusing technique used here.
    a: Option<A>,
    b: Option<B>,
    f: F,
}

impl<A, B, F> MixedChain<A, B, F> {
    /// Builds a new [`MixedChain`] iterator.
    #[inline]
    fn new(a: A, b: B, f: F) -> Self {
        Self {
            a: Some(a),
            b: Some(b),
            f,
        }
    }

    #[inline]
    fn extract<T, E>(&mut self) -> Option<T>
    where
        A: Iterator,
        B: Iterator,
        F: FnMut(Either<A::Item, B::Item>) -> T,
        E: Extract<A> + Extract<B>,
    {
        let maybe_item = match self.a {
            Some(ref mut iter) => match left_map(E::extract(iter), &mut self.f) {
                None => {
                    self.a = None;
                    None
                }
                item => item,
            },
            _ => None,
        };
        match maybe_item {
            None => match self.b {
                Some(ref mut iter) => right_map(E::extract(iter), &mut self.f),
                _ => None,
            },
            item => item,
        }
    }
}

#[inline]
fn left<F, L, R, T>(item: L, mut f: F) -> T
where
    F: FnMut(Either<L, R>) -> T,
{
    f(Either::Left(item))
}

#[inline]
fn left_map<F, L, R, T>(item: Option<L>, f: &mut F) -> Option<T>
where
    F: FnMut(Either<L, R>) -> T,
{
    item.map(|i| left(i, f))
}

#[inline]
fn right<F, L, R, T>(item: R, mut f: F) -> T
where
    F: FnMut(Either<L, R>) -> T,
{
    f(Either::Right(item))
}

#[inline]
fn right_map<F, L, R, T>(item: Option<R>, f: &mut F) -> Option<T>
where
    F: FnMut(Either<L, R>) -> T,
{
    item.map(|i| right(i, f))
}

impl<A, B, F, T> Iterator for MixedChain<A, B, F>
where
    A: Iterator,
    B: Iterator,
    F: FnMut(Either<A::Item, B::Item>) -> T,
{
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.extract::<_, Next>()
    }

    #[inline]
    // TODO: #[rustc_inherit_overflow_checks]
    fn count(self) -> usize {
        let Self { a, b, mut f } = self;
        let a_count = match a {
            Some(a) => a.map(|a| left(a, &mut f)).count(),
            None => 0,
        };
        let b_count = match b {
            Some(b) => b.map(|b| right(b, &mut f)).count(),
            None => 0,
        };
        a_count + b_count
    }

    #[inline]
    fn fold<Acc, FoldF>(self, mut acc: Acc, mut fold_f: FoldF) -> Acc
    where
        FoldF: FnMut(Acc, Self::Item) -> Acc,
    {
        let Self { a, b, mut f } = self;
        if let Some(a) = a {
            acc = a.fold(acc, |accum, a| fold_f(accum, left(a, &mut f)));
        }
        if let Some(b) = b {
            acc = b.fold(acc, |accum, b| fold_f(accum, right(b, &mut f)));
        }
        acc
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        // NOTE: Must exhaust a before b.
        let Self { a, b, mut f } = self;
        let a_last = match a {
            Some(a) => a.map(|a| left(a, &mut f)).last(),
            None => None,
        };
        let b_last = match b {
            Some(b) => b.map(|b| right(b, &mut f)).last(),
            None => None,
        };
        b_last.or(a_last)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match (&self.a, &self.b) {
            (Some(a), Some(b)) => {
                let (a_lower, a_upper) = a.size_hint();
                let (b_lower, b_upper) = b.size_hint();
                let lower = a_lower.saturating_add(b_lower);
                let upper = match (a_upper, b_upper) {
                    (Some(x), Some(y)) => x.checked_add(y),
                    _ => None,
                };
                (lower, upper)
            }
            (Some(a), _) => a.size_hint(),
            (_, Some(b)) => b.size_hint(),
            _ => (0, Some(0)),
        }
    }
}

impl<A, B, F, T> DoubleEndedIterator for MixedChain<A, B, F>
where
    A: DoubleEndedIterator,
    B: DoubleEndedIterator,
    F: FnMut(Either<A::Item, B::Item>) -> T,
{
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.extract::<_, NextBack>()
    }

    #[inline]
    fn rfold<Acc, FoldF>(self, mut acc: Acc, mut fold_f: FoldF) -> Acc
    where
        FoldF: FnMut(Acc, Self::Item) -> Acc,
    {
        let Self { a, b, mut f } = self;
        if let Some(b) = b {
            acc = b.rfold(acc, |accum, b| fold_f(accum, right(b, &mut f)));
        }
        if let Some(a) = a {
            acc = a.rfold(acc, |accum, a| fold_f(accum, left(a, &mut f)));
        }
        acc
    }
}

// NOTE: *Both* must be fused to handle double-ended iterators.
impl<A, B, F, T> FusedIterator for MixedChain<A, B, F>
where
    A: FusedIterator,
    B: FusedIterator,
    F: FnMut(Either<A::Item, B::Item>) -> T,
{
}

/// Creates a mixed chain iterator.
#[inline]
pub fn mixed_chain<A, B, F, T>(a: A, b: B, f: F) -> MixedChain<A::IntoIter, B::IntoIter, F>
where
    A: IntoIterator,
    B: IntoIterator,
    F: FnMut(Either<A::Item, B::Item>) -> T,
{
    MixedChain::new(a.into_iter(), b.into_iter(), f)
}
