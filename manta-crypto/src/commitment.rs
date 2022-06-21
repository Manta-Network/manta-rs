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

//! Commitment Schemes

/// Commitment Scheme
///
/// See [`security`] for security properties that should be attached to [`CommitmentScheme`]
/// instances.
pub trait CommitmentScheme<COM = ()> {
    /// Randomness Type
    type Randomness;

    /// Input Type
    type Input;

    /// Output Type
    type Output;

    /// Commits to the `input` value using `randomness`.
    fn commit(
        &self,
        randomness: &Self::Randomness,
        input: &Self::Input,
        compiler: &mut COM,
    ) -> Self::Output;
}

/// Security Assumptions
///
/// The following outlines some standard security assumptions for commitment schemes. These security
/// properties can be attached to general types that don't exactly conform to the
/// [`CommitmentScheme`] `trait` to describe the same cryptographic assumptions or guarantees given
/// by the type.
pub mod security {
    /// Binding Security Property
    ///
    /// This is a generic binding assumption marker whenever one is unsure which kind of binding
    /// security to require or use. See [`ComputationalBinding`], [`StatisticalBinding`], and
    /// [`PerfectBinding`] for more details on concrete security assumptions.
    pub trait Binding {}

    /// Computational Binding Security Property
    pub trait ComputationalBinding: Binding {}

    /// Statistical Binding Security Property
    pub trait StatisticalBinding: Binding {}

    /// Perfect Binding Security Property
    pub trait PerfectBinding: ComputationalBinding + StatisticalBinding {}

    /// Hiding Security Property
    ///
    /// This is a generic hiding assumption marker whenever one is unsure which kind of hiding
    /// security to require or use. See [`ComputationalHiding`], [`StatisticalHiding`], and
    /// [`PerfectHiding`] for more details on concrete security assumptions.
    pub trait Hiding {}

    /// Computational Hiding Security Property
    pub trait ComputationalHiding: Hiding {}

    /// Statistical Hiding Security Property
    pub trait StatisticalHiding: Hiding {}

    /// Perfect Hiding Security Property
    pub trait PerfectHiding: ComputationalHiding + StatisticalHiding {}
}
