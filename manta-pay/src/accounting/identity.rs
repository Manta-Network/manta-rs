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

//! Identity Implementations

use crate::{accounting::config::Configuration, crypto::merkle_tree::ConfigConverter};
use manta_accounting::{identity, transfer};
use manta_crypto::merkle_tree::{self, full::Full};

/// Unspent Transaction Output
pub type Utxo = identity::Utxo<Configuration>;

/// Void Number
pub type VoidNumber = identity::VoidNumber<Configuration>;

/// UTXO Set Parameters
pub type Parameters = merkle_tree::Parameters<ConfigConverter<Configuration>>;

/// UTXO Set Root
pub type Root = merkle_tree::Root<ConfigConverter<Configuration>>;

/// UTXO Set Path
pub type Path = merkle_tree::Path<ConfigConverter<Configuration>>;

/// Identity Constraint System Variables
pub mod constraint {
    use super::*;
    use crate::{
        accounting::config::ConstraintSystem,
        crypto::merkle_tree::constraint as merkle_tree_constraint,
    };
    use manta_crypto::{
        accumulator::Verifier,
        constraint::{reflection::HasAllocation, Allocation, Constant, Variable},
    };
    use manta_util::concatenate;

    /// UTXO Set Parameters Variable
    pub type ParametersVar = merkle_tree_constraint::ParametersVar<Configuration>;

    /// UTXO Set Root Variable
    pub type RootVar = merkle_tree_constraint::RootVar<Configuration>;

    /// UTXO Set Path Variable
    pub type PathVar = merkle_tree_constraint::PathVar<Configuration>;

    /// UTXO Set Verifier Variable
    #[derive(Clone)]
    pub struct UtxoSetVerifier(ParametersVar);

    impl Variable<ConstraintSystem> for UtxoSetVerifier {
        type Type = Parameters;

        type Mode = Constant;

        #[inline]
        fn new(ps: &mut ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
            let (this, mode) = allocation.into_known();
            Self(this.known(ps, mode))
        }
    }

    impl Verifier for UtxoSetVerifier {
        type Item = UtxoVar;

        type Witness = <ParametersVar as Verifier>::Witness;

        type Output = <ParametersVar as Verifier>::Output;

        type Verification = <ParametersVar as Verifier>::Verification;

        #[inline]
        fn verify(
            &self,
            item: &Self::Item,
            witness: &Self::Witness,
            output: &Self::Output,
        ) -> Self::Verification {
            self.0.verify(output, witness, &concatenate!(item))
        }
    }
}
