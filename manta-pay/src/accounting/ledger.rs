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

//! Ledger Implementation

// FIXME: Migrate this to new ledger abstraction. This will most likely go to `wallet` since it
//        represents the "native" ledger rather than the blockchain ledger.

use crate::{
    accounting::config::{Configuration, ConstraintSystem},
    crypto::merkle_tree::{constraint as merkle_tree_constraint, ConfigConverter},
};
use alloc::{collections::BTreeSet, vec, vec::Vec};
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2s,
};
use manta_accounting::identity;
use manta_crypto::{
    constraint::{reflection::HasAllocation, Allocation, Constant, Variable},
    merkle_tree::{self, single_path::SinglePath, Tree},
    set::{constraint::VerifierVariable, MembershipProof, VerifiedSet, Verifier},
};
use manta_util::{as_bytes, concatenate, into_array_unchecked};

/// Unspent Transaction Output
type Utxo = identity::Utxo<Configuration>;

/// UTXO Variable
type UtxoVar = identity::constraint::UtxoVar<Configuration>;

/// UTXO Shard Root
type Root = merkle_tree::Root<ConfigConverter<Configuration>>;

/// UTXO Shard Root Variable
type RootVar = merkle_tree_constraint::RootVar<Configuration>;

/// UTXO Set Parameters
type Parameters = merkle_tree::Parameters<ConfigConverter<Configuration>>;

/// UTXO Set Parameters Variable
type ParametersVar = merkle_tree_constraint::ParametersVar<Configuration>;

/// UTXO Set Path
type Path = merkle_tree::Path<ConfigConverter<Configuration>>;

/// UTXO Set Path Variable
type PathVar = merkle_tree_constraint::PathVar<Configuration>;

/// UTXO Shard
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct UtxoShard {
    /// Shard Root
    root: Root,

    /// Unspent Transaction Outputs
    utxos: SinglePath<ConfigConverter<Configuration>>,
}

/// UTXO Set Verifier
#[derive(Clone)]
pub struct UtxoSetVerifier(Parameters);

impl Verifier for UtxoSetVerifier {
    type Item = Utxo;

    type Public = Root;

    type Secret = Path;

    #[inline]
    fn verify(&self, public: &Self::Public, secret: &Self::Secret, item: &Self::Item) -> bool {
        self.0.verify(public, secret, &as_bytes!(item))
    }
}

/// UTXO Set
#[derive(Clone)]
pub struct UtxoSet {
    /// UTXO Shards
    shards: [UtxoShard; Self::SHARD_COUNT],

    /// UTXO Set
    _utxos: BTreeSet<Utxo>,

    /// Merkle Tree Parameters
    parameters: UtxoSetVerifier,
}

impl UtxoSet {
    const SHARD_COUNT: usize = 256;

    /// Builds a new [`UtxoSet`].
    #[inline]
    pub fn new(parameters: Parameters) -> Self {
        Self {
            shards: into_array_unchecked(vec![Default::default(); Self::SHARD_COUNT]),
            _utxos: Default::default(),
            parameters: UtxoSetVerifier(parameters),
        }
    }

    /// Computes the shard index of this `utxo`.
    #[inline]
    fn shard_index(utxo: &Utxo) -> usize {
        let mut hasher = VarBlake2s::new(1).expect("Failed to generate Variable Blake2s hasher.");
        hasher.update(&as_bytes!(utxo));
        let mut res: usize = 0;
        hasher.finalize_variable(|x| res = x[0] as usize);
        res
    }

    /// Returns a shared reference to the shard which this `utxo` would be stored in.
    #[inline]
    pub fn shard(&self, utxo: &Utxo) -> &UtxoShard {
        &self.shards[Self::shard_index(utxo)]
    }

    /// Returns `true` if the `root` belongs to some shard.
    #[inline]
    pub fn root_exists(&self, root: &Root) -> bool {
        self.shards.iter().any(move |s| s.root == *root)
    }

    /// Returns `true` if the `utxo` belongs to the shard it would be stored in.
    #[inline]
    pub fn utxo_exists(&self, utxo: &Utxo) -> bool {
        let _ = utxo;
        // TODO: self.utxos.contains(utxo)
        todo!()
    }
}

impl VerifiedSet for UtxoSet {
    type Item = Utxo;

    type Public = Root;

    type Secret = Path;

    type Verifier = UtxoSetVerifier;

    #[inline]
    fn capacity(&self) -> usize {
        todo!()
    }

    #[inline]
    fn len(&self) -> usize {
        // FIXME: Implement.
        todo!()
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        if self.utxo_exists(item) {
            return false;
        }
        if !self.shards[Self::shard_index(item)]
            .utxos
            .push(&self.parameters.0, &as_bytes!(item))
        {
            return false;
        }
        // FIXME: self.utxos.insert(item);
        true
    }

    #[inline]
    fn insert_provable(&mut self, item: &Self::Item) -> bool {
        // FIXME: This is not implementable!
        false
    }

    #[inline]
    fn verifier(&self) -> &Self::Verifier {
        &self.parameters
    }

    #[inline]
    fn check_public(&self, public: &Self::Public) -> bool {
        self.root_exists(public)
    }

    #[inline]
    fn get_membership_proof(&self, item: &Self::Item) -> Option<MembershipProof<Self::Verifier>> {
        let _ = item;

        // TODO: Return a more informative error.

        /* TODO:
        let utxos = &self.shards[Self::shard_index(item)].utxos;
        match utxos.iter().position(move |u| u == item) {
            Some(index) => MerkleTree::new(&self.parameters, utxos)
                .ok_or(())?
                .get_containment_proof(index)
                .ok_or(()),
            _ => Err(()),
        }
        */

        todo!()
    }

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.utxo_exists(item)
    }
}

/// UTXO Set Verifier Variable
#[derive(Clone)]
pub struct UtxoSetVerifierVar(ParametersVar);

impl Variable<ConstraintSystem> for UtxoSetVerifierVar {
    type Type = UtxoSetVerifier;

    type Mode = Constant;

    #[inline]
    fn new(ps: &mut ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        let (this, mode) = allocation.into_known();
        Self(this.0.known(ps, mode))
    }
}

impl HasAllocation<ConstraintSystem> for UtxoSetVerifier {
    type Variable = UtxoSetVerifierVar;
    type Mode = Constant;
}

impl VerifierVariable<ConstraintSystem> for UtxoSetVerifierVar {
    type ItemVar = UtxoVar;

    #[inline]
    fn assert_valid_membership_proof(
        &self,
        public: &RootVar,
        secret: &PathVar,
        item: &UtxoVar,
        cs: &mut ConstraintSystem,
    ) {
        let _ = cs;
        self.0.assert_verified(public, secret, &concatenate!(item))
    }
}
