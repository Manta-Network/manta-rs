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
    accounting::config::{Configuration, ConstraintSystem, ProofSystem},
    crypto::{
        ies::EncryptedAsset,
        merkle_tree::{constraint as merkle_tree_constraint, ConfigConverter},
    },
};
use alloc::{collections::BTreeSet, vec, vec::Vec};
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2s,
};
use manta_accounting::identity;
use manta_crypto::{
    constraint::{self, reflection::HasAllocation, Allocation, Constant, Variable},
    merkle_tree::{self, single_leaf::SingleLeaf, Tree},
    set::{constraint::VerifiedSetVariable, ContainmentProof, Set, VerifiedSet},
};
use manta_util::{as_bytes, concatenate, into_array_unchecked};

/// Void Number
type VoidNumber = identity::VoidNumber<Configuration>;

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
    utxos: SingleLeaf<ConfigConverter<Configuration>>,
}

/// UTXO Set
#[derive(Clone)]
pub struct UtxoSet {
    /// UTXO Shards
    shards: [UtxoShard; Self::SHARD_COUNT],

    /// UTXO Set
    _utxos: BTreeSet<Utxo>,

    /// Merkle Tree Parameters
    parameters: Parameters,
}

impl UtxoSet {
    const SHARD_COUNT: usize = 256;

    /// Builds a new [`UtxoSet`].
    #[inline]
    pub fn new(parameters: Parameters) -> Self {
        Self {
            shards: into_array_unchecked(vec![Default::default(); Self::SHARD_COUNT]),
            _utxos: Default::default(),
            parameters,
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

impl Set for UtxoSet {
    type Item = Utxo;

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.utxo_exists(item)
    }

    #[inline]
    fn try_insert(&mut self, item: Self::Item) -> Result<(), Self::Item> {
        // TODO: Distinguish between both kinds of errors.
        if self.utxo_exists(&item) {
            return Err(item);
        }
        if !self.shards[Self::shard_index(&item)]
            .utxos
            .push(&self.parameters, &as_bytes!(&item))
        {
            return Err(item);
        }
        // FIXME: self.utxos.insert(item);
        Ok(())
    }
}

impl VerifiedSet for UtxoSet {
    type Public = Root;

    type Secret = Path;

    type ContainmentError = ();

    #[inline]
    fn check_public_input(&self, public_input: &Self::Public) -> bool {
        self.root_exists(public_input)
    }

    #[inline]
    fn check_containment_proof(
        &self,
        public_input: &Self::Public,
        secret_witness: &Self::Secret,
        item: &Self::Item,
    ) -> bool {
        // FIXME: Leaf should be `Utxo` not `[u8]`.
        self.parameters
            .verify_path(secret_witness, public_input, &as_bytes!(item))
    }

    #[inline]
    fn get_containment_proof(
        &self,
        item: &Self::Item,
    ) -> Result<ContainmentProof<Self>, Self::ContainmentError> {
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
}

/// UTXO Set Variable
#[derive(Clone)]
pub struct UtxoSetVar(ParametersVar);

impl Variable<ConstraintSystem> for UtxoSetVar {
    type Type = UtxoSet;

    type Mode = Constant;

    #[inline]
    fn new(ps: &mut ConstraintSystem, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        let (this, mode) = allocation.into_known();
        Self(this.parameters.known(ps, mode))
    }
}

impl HasAllocation<ConstraintSystem> for UtxoSet {
    type Variable = UtxoSetVar;
    type Mode = Constant;
}

impl VerifiedSetVariable<ConstraintSystem> for UtxoSetVar {
    type ItemVar = UtxoVar;

    #[inline]
    fn assert_valid_containment_proof(
        &self,
        public_input: &RootVar,
        secret_witness: &PathVar,
        item: &UtxoVar,
        cs: &mut ConstraintSystem,
    ) {
        let _ = cs;
        self.0
            .assert_verified(public_input, secret_witness, &concatenate!(item))
    }
}

/// Ledger
pub struct Ledger {
    /// Void Numbers
    _void_numbers: Vec<VoidNumber>,

    /// Unspent Transaction Outputs
    _utxos: UtxoSet,

    /// Encrypted Assets
    _encrypted_assets: Vec<EncryptedAsset>,

    /// Verifying Context
    _verifying_context: <ProofSystem as constraint::ProofSystem>::VerifyingContext,
}
