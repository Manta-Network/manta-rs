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

// FIXME: How should we handle serdes?

use crate::{
    accounting::config::{
        Configuration, PedersenCommitmentProjectiveCurve, PedersenCommitmentProjectiveCurveVar,
        PedersenCommitmentWindowParameters, ProofSystem,
    },
    crypto::{
        ies::EncryptedAsset,
        merkle_tree::{self, MerkleTree},
    },
};
use alloc::{vec, vec::Vec};
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2s,
};
use manta_accounting::{identity, Ledger as LedgerTrait, ProofPostError};
use manta_crypto::{
    constraint::{self, reflection::HasAllocation, Allocation, Constant, Variable},
    set::{constraint::VerifiedSetVariable, ContainmentProof, Set, VerifiedSet},
};
use manta_util::{as_bytes, concatenate, into_array_unchecked};

/// Void Number
type VoidNumber = identity::VoidNumber<Configuration>;

/// Unspent Transaction Output
type Utxo = identity::Utxo<Configuration>;

/// UTXO Variable
type UtxoVar = identity::UtxoVar<Configuration>;

/// UTXO Shard Root
type Root = merkle_tree::RootWrapper<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// UTXO Shard Root Variable
type RootVar = merkle_tree::RootVar<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// UTXO Set Parameters
type Parameters = merkle_tree::ParametersWrapper<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// UTXO Set Parameters Variable
type ParametersVar = merkle_tree::ParametersVar<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// UTXO Set Path
type Path = merkle_tree::PathWrapper<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// UTXO Set Path Variable
type PathVar = merkle_tree::PathVar<
    PedersenCommitmentWindowParameters,
    PedersenCommitmentProjectiveCurve,
    PedersenCommitmentProjectiveCurveVar,
>;

/// UTXO Shard
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct UtxoShard {
    /// Shard Root
    root: Root,

    /// Unspent Transaction Outputs
    utxos: Vec<Utxo>,
}

/// UTXO Set
#[derive(Clone)]
pub struct UtxoSet {
    /// UTXO Shards
    shards: [UtxoShard; Self::SHARD_COUNT],

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
        self.shard(utxo).utxos.iter().any(move |u| u == utxo)
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
        // FIXME: This will panic because `shard.utxos.len()` is not always a power of two.
        let shard = &mut self.shards[Self::shard_index(&item)];
        if shard.utxos.contains(&item) {
            return Err(item);
        }
        shard.utxos.push(item);
        match MerkleTree::build_root_wrapped(&self.parameters, &shard.utxos) {
            Some(root) => {
                shard.root = root;
                Ok(())
            }
            _ => Err(shard.utxos.pop().unwrap()),
        }
    }
}

impl VerifiedSet for UtxoSet {
    type Public = Root;

    type Secret = Path;

    // TODO: Give a more informative error.
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
        self.parameters.verify(public_input, secret_witness, item)
    }

    #[inline]
    fn get_containment_proof(
        &self,
        item: &Self::Item,
    ) -> Result<ContainmentProof<Self>, Self::ContainmentError> {
        // FIXME: This will panic because `utxos.len()` is not always a power of two.
        let utxos = &self.shards[Self::shard_index(item)].utxos;
        match utxos.iter().position(move |u| u == item) {
            Some(index) => MerkleTree::from_wrapped(&self.parameters, utxos)
                .ok_or(())?
                .get_wrapped_containment_proof(index)
                .ok_or(()),
            _ => Err(()),
        }
    }
}

/// UTXO Set Variable
#[derive(Clone)]
pub struct UtxoSetVar(ParametersVar);

impl Variable<ProofSystem> for UtxoSetVar {
    type Mode = Constant;
    type Type = UtxoSet;
}

impl Alloc<ProofSystem> for UtxoSet {
    type Mode = Constant;

    type Variable = UtxoSetVar;

    #[inline]
    fn variable<'t>(
        ps: &mut ProofSystem,
        allocation: impl Into<Allocation<'t, Self, ProofSystem>>,
    ) -> Self::Variable
    where
        Self: 't,
    {
        UtxoSetVar(match allocation.into() {
            Allocation::Known(this, mode) => this.parameters.as_known(ps, mode),
            _ => unreachable!(
                "Since we use a constant allocation mode, we always know the variable value."
            ),
        })
    }
}

impl VerifiedSetVariable<ProofSystem> for UtxoSetVar {
    #[inline]
    fn assert_valid_containment_proof(
        &self,
        public_input: &RootVar,
        secret_witness: &PathVar,
        item: &UtxoVar,
        ps: &mut ProofSystem,
    ) {
        let _ = ps;
        self.0
            .assert_verified(public_input, secret_witness, &concatenate!(item))
    }
}

/// Ledger
pub struct Ledger {
    /// Void Numbers
    void_numbers: Vec<VoidNumber>,

    /// Unspent Transaction Outputs
    utxos: UtxoSet,

    /// Encrypted Assets
    encrypted_assets: Vec<EncryptedAsset>,
}

impl LedgerTrait for Ledger {
    type VoidNumber = VoidNumber;

    type Utxo = Utxo;

    type UtxoSet = UtxoSet;

    type EncryptedAsset = EncryptedAsset;

    type ProofSystem = ProofSystem;

    #[inline]
    fn utxos(&self) -> &Self::UtxoSet {
        &self.utxos
    }

    #[inline]
    fn is_unspent(&self, void_number: &Self::VoidNumber) -> bool {
        !self.void_numbers.contains(void_number)
    }

    #[inline]
    fn try_post_void_number(
        &mut self,
        void_number: Self::VoidNumber,
    ) -> Result<(), Self::VoidNumber> {
        if self.void_numbers.contains(&void_number) {
            return Err(void_number);
        }
        self.void_numbers.push(void_number);
        Ok(())
    }

    #[inline]
    fn try_post_utxo(&mut self, utxo: Self::Utxo) -> Result<(), Self::Utxo> {
        self.utxos.try_insert(utxo)
    }

    #[inline]
    fn try_post_encrypted_asset(
        &mut self,
        encrypted_asset: Self::EncryptedAsset,
    ) -> Result<(), Self::EncryptedAsset> {
        self.encrypted_assets.push(encrypted_asset);
        Ok(())
    }

    #[inline]
    fn check_proof(
        &self,
        proof: <Self::ProofSystem as constraint::ProofSystem>::Proof,
    ) -> Result<(), ProofPostError<Self>> {
        let _ = proof;
        todo!()
    }
}
