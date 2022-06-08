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

//! Algebraic Constructions

/// Ring of Scalars
pub trait Scalar<COM = ()> {
    /// Adds `rhs` to `self` in the ring.
    fn add(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Multiplies `self` by `rhs` in the ring.
    fn mul(&self, rhs: &Self, compiler: &mut COM) -> Self;
}

/// Group
pub trait Group<COM = ()> {
    /// Ring of Scalars
    type Scalar: Scalar<COM>;

    /// Adds `rhs` to `self` in the group.
    fn add(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Multiplies `self` by `scalar` in the group.
    fn mul(&self, scalar: &Self::Scalar, compiler: &mut COM) -> Self;
}

/// Security Assumptions
///
/// The following outline some standard security assumptions for cryptographic protocols built on
/// [`Group`] types.
pub mod security {
    /// Discrete Logarithm Hardness Assumption
    ///
    /// For a [`Group`](super::Group) `G`, it should be infeasible to find a procedure `f` that
    /// makes this function return `true`:
    ///
    /// ```text
    /// fn solve<F>(g: G, y: G, f: F) -> bool
    /// where
    ///     F: FnOnce(G, G) -> G::Scalar,
    /// {
    ///     y == g.mul(f(g, y))
    /// }
    /// ```
    pub trait DL {}

    /// Computational Diffie-Hellman Hardness Assumption
    ///
    /// For a [`Group`](super::Group) `G`, it should be infeasible to find a procedure `f` that
    /// makes this function return `true`:
    ///
    /// ```text
    /// fn solve<F>(g: G, a: G::Scalar, b: G::Scalar, f: F) -> bool
    /// where
    ///     F: FnOnce(G, G, G) -> G,
    /// {
    ///     f(g, g.mul(a), g.mul(b)) == g.mul(a.mul(b))
    /// }
    /// ```
    pub trait CDH: DL {}

    /// Decisional Diffie-Hellman Hardness Assumption
    ///
    /// For a [`Group`](super::Group) `G`, it should be infeasible to distinguish the probability
    /// distributions over the following two functions when [`G::Scalar](super::Group::Scalar)
    /// inputs are sampled uniformly from their domain (and `g` the generator is fixed):
    ///
    /// ```text
    /// fn dh_triple(g: G, a: G::Scalar, b: G::Scalar) -> (G, G, G) {
    ///     (g.mul(a), g.mul(b), g.mul(a.mul(b)))
    /// }
    ///
    /// fn random_triple(g: G, a: G::Scalar, b: G::Scalar, c: G::Scalar) -> (G, G, G) {
    ///     (g.mul(a), g.mul(b), g.mul(c))
    /// }
    /// ```
    pub trait DDH: CDH {}
}
