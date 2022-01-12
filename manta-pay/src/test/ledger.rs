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

//! Test Ledger Implementation

use crate::config::{
    Config, EncryptedNote, MerkleTreeConfiguration, MultiVerifyingContext, ProofSystem,
    TransferPost, Utxo, VoidNumber,
};
use alloc::{rc::Rc, vec::Vec};
use async_std::sync::RwLock;
use core::convert::Infallible;
use indexmap::IndexSet;
use manta_accounting::{
    asset::{AssetId, AssetValue},
    transfer::{
        canonical::TransferShape, AccountBalance, InvalidSinkAccount, InvalidSourceAccount, Proof,
        ReceiverLedger, ReceiverPostingKey, SenderLedger, SenderPostingKey, SinkPostingKey,
        SourcePostingKey, TransferLedger, TransferLedgerSuperPostingKey, TransferPostingKey,
        UtxoSetOutput,
    },
    wallet::ledger::{Connection, PullResponse, PullResult, PushResponse, PushResult},
};
use manta_crypto::{
    constraint::ProofSystem as _,
    merkle_tree::{self, forest::Configuration, Tree},
};
use manta_util::{future::LocalBoxFuture, into_array_unchecked};
use std::collections::{HashMap, HashSet};

/// UTXO Merkle Forest Type
pub type UtxoMerkleForest = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::single_path::SinglePath<MerkleTreeConfiguration>,
    256,
>;

/// Wrap Type
#[derive(Clone, Copy)]
pub struct Wrap<T>(T);

impl<T> AsRef<T> for Wrap<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// Wrap Pair Type
#[derive(Clone, Copy)]
pub struct WrapPair<L, R>(L, R);

impl<L, R> AsRef<R> for WrapPair<L, R> {
    #[inline]
    fn as_ref(&self) -> &R {
        &self.1
    }
}

/// Account Id
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(pub u64);

/// Ledger
#[derive(Debug)]
pub struct Ledger {
    /// Void Numbers
    void_numbers: IndexSet<VoidNumber>,

    /// UTXOs
    utxos: HashSet<Utxo>,

    /// Shards
    shards: HashMap<u8, HashMap<u64, (Utxo, EncryptedNote)>>,

    /// UTXO Forest
    utxo_forest: UtxoMerkleForest,

    /// Account Table
    accounts: HashMap<AccountId, HashMap<AssetId, AssetValue>>,

    /// Verifying Contexts
    verifying_context: MultiVerifyingContext,
}

impl Ledger {
    /// Builds an empty [`Ledger`].
    #[inline]
    pub fn new(
        utxo_forest_parameters: merkle_tree::Parameters<MerkleTreeConfiguration>,
        verifying_context: MultiVerifyingContext,
    ) -> Self {
        Self {
            void_numbers: Default::default(),
            utxos: Default::default(),
            shards: (0..=255).map(move |i| (i, Default::default())).collect(),
            utxo_forest: UtxoMerkleForest::new(utxo_forest_parameters),
            accounts: Default::default(),
            verifying_context,
        }
    }

    /// Sets the public balance of `account` in assets with `id` to `value`.
    #[inline]
    pub fn set_public_balance(&mut self, account: AccountId, id: AssetId, value: AssetValue) {
        self.accounts.entry(account).or_default().insert(id, value);
    }
}

impl SenderLedger<Config> for Ledger {
    type ValidVoidNumber = Wrap<VoidNumber>;
    type ValidUtxoSetOutput = Wrap<UtxoSetOutput<Config>>;
    type SuperPostingKey = (Wrap<()>, ());

    #[inline]
    fn is_unspent(&self, void_number: VoidNumber) -> Option<Self::ValidVoidNumber> {
        if self.void_numbers.contains(&void_number) {
            None
        } else {
            Some(Wrap(void_number))
        }
    }

    #[inline]
    fn has_matching_utxo_set_output(
        &self,
        output: UtxoSetOutput<Config>,
    ) -> Option<Self::ValidUtxoSetOutput> {
        for tree in self.utxo_forest.forest.as_ref() {
            if tree.root() == &output {
                return Some(Wrap(output));
            }
        }
        None
    }

    #[inline]
    fn spend(
        &mut self,
        utxo_set_output: Self::ValidUtxoSetOutput,
        void_number: Self::ValidVoidNumber,
        super_key: &Self::SuperPostingKey,
    ) {
        let _ = (utxo_set_output, super_key);
        self.void_numbers.insert(void_number.0);
    }
}

impl ReceiverLedger<Config> for Ledger {
    type ValidUtxo = Wrap<Utxo>;
    type SuperPostingKey = (Wrap<()>, ());

    #[inline]
    fn is_not_registered(&self, utxo: Utxo) -> Option<Self::ValidUtxo> {
        if self.utxos.contains(&utxo) {
            None
        } else {
            Some(Wrap(utxo))
        }
    }

    #[inline]
    fn register(
        &mut self,
        utxo: Self::ValidUtxo,
        note: EncryptedNote,
        super_key: &Self::SuperPostingKey,
    ) {
        let _ = super_key;
        let shard = self
            .shards
            .get_mut(&MerkleTreeConfiguration::tree_index(&utxo.0))
            .expect("All shards exist when the ledger is constructed.");
        let len = shard.len();
        shard.insert(len as u64, (utxo.0, note));
        self.utxos.insert(utxo.0);
        self.utxo_forest.push(&utxo.0);
    }
}

impl TransferLedger<Config> for Ledger {
    type AccountId = AccountId;
    type Event = ();
    type ValidSourceAccount = WrapPair<Self::AccountId, AssetValue>;
    type ValidSinkAccount = WrapPair<Self::AccountId, AssetValue>;
    type ValidProof = Wrap<()>;
    type SuperPostingKey = ();

    #[inline]
    fn check_source_accounts<I>(
        &self,
        asset_id: AssetId,
        sources: I,
    ) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccount<Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, AssetValue)>,
    {
        sources
            .map(|(account_id, withdraw)| {
                match self.accounts.get(&account_id) {
                    Some(map) => match map.get(&asset_id) {
                        Some(balance) => {
                            if balance >= &withdraw {
                                Ok(WrapPair(account_id, withdraw))
                            } else {
                                Err(InvalidSourceAccount {
                                    account_id,
                                    balance: AccountBalance::Known(*balance),
                                    withdraw,
                                })
                            }
                        }
                        _ => {
                            // FIXME: What about zero values in `sources`?
                            Err(InvalidSourceAccount {
                                account_id,
                                balance: AccountBalance::Known(AssetValue(0)),
                                withdraw,
                            })
                        }
                    },
                    _ => Err(InvalidSourceAccount {
                        account_id,
                        balance: AccountBalance::UnknownAccount,
                        withdraw,
                    }),
                }
            })
            .collect()
    }

    #[inline]
    fn check_sink_accounts<I>(
        &self,
        sinks: I,
    ) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccount<Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, AssetValue)>,
    {
        sinks
            .map(move |(account_id, deposit)| {
                if self.accounts.contains_key(&account_id) {
                    Ok(WrapPair(account_id, deposit))
                } else {
                    Err(InvalidSinkAccount { account_id })
                }
            })
            .collect()
    }

    #[inline]
    fn is_valid(
        &self,
        asset_id: Option<AssetId>,
        sources: &[SourcePostingKey<Config, Self>],
        senders: &[SenderPostingKey<Config, Self>],
        receivers: &[ReceiverPostingKey<Config, Self>],
        sinks: &[SinkPostingKey<Config, Self>],
        proof: Proof<Config>,
    ) -> Option<(Self::ValidProof, Self::Event)> {
        let verifying_context = self.verifying_context.select(TransferShape::select(
            asset_id.is_some(),
            sources.len(),
            senders.len(),
            receivers.len(),
            sinks.len(),
        )?);
        ProofSystem::verify(
            &TransferPostingKey::generate_proof_input(asset_id, sources, senders, receivers, sinks),
            &proof,
            verifying_context,
        )
        .ok()?
        .then(move || (Wrap(()), ()))
    }

    #[inline]
    fn update_public_balances(
        &mut self,
        asset_id: AssetId,
        sources: Vec<SourcePostingKey<Config, Self>>,
        sinks: Vec<SinkPostingKey<Config, Self>>,
        proof: Self::ValidProof,
        super_key: &TransferLedgerSuperPostingKey<Config, Self>,
    ) {
        let _ = (proof, super_key);
        for WrapPair(account_id, withdraw) in sources {
            *self
                .accounts
                .get_mut(&account_id)
                .expect("We checked that this account exists.")
                .get_mut(&asset_id)
                .expect("We checked that this account has enough balance to withdraw.") -= withdraw;
        }
        for WrapPair(account_id, deposit) in sinks {
            *self
                .accounts
                .get_mut(&account_id)
                .expect("We checked that this account exists.")
                .entry(asset_id)
                .or_default() += deposit;
        }
    }
}

/// Checkpoint
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Checkpoint {
    /// Receiver Index
    pub receiver_index: [usize; 256],

    /// Sender Index
    pub sender_index: usize,
}

impl Checkpoint {
    /// Builds a new [`Checkpoint`] from `receiver_index` and `sender_index`.
    #[inline]
    pub fn new(receiver_index: [usize; 256], sender_index: usize) -> Self {
        Self {
            receiver_index,
            sender_index,
        }
    }
}

impl Default for Checkpoint {
    #[inline]
    fn default() -> Self {
        Self::new([0; 256], 0)
    }
}

/// Ledger Connection
pub struct LedgerConnection {
    /// Ledger Account
    account: AccountId,

    /// Ledger Access
    ledger: Rc<RwLock<Ledger>>,
}

impl LedgerConnection {
    /// Builds a new [`LedgerConnection`] for `account` and `ledger`.
    #[inline]
    pub fn new(account: AccountId, ledger: Rc<RwLock<Ledger>>) -> Self {
        Self { account, ledger }
    }
}

impl Connection<Config> for LedgerConnection {
    type Checkpoint = Checkpoint;
    type ReceiverChunk = Vec<(Utxo, EncryptedNote)>;
    type SenderChunk = Vec<VoidNumber>;
    type Error = Infallible;

    #[inline]
    fn pull<'s>(
        &'s mut self,
        checkpoint: &'s Self::Checkpoint,
    ) -> LocalBoxFuture<'s, PullResult<Config, Self>> {
        Box::pin(async {
            let ledger = self.ledger.read().await;
            let mut receivers = Vec::new();
            for (i, mut index) in checkpoint.receiver_index.iter().copied().enumerate() {
                let shard = &ledger.shards[&(i as u8)];
                while let Some(entry) = shard.get(&(index as u64)) {
                    receivers.push(*entry);
                    index += 1;
                }
            }
            let senders = ledger
                .void_numbers
                .iter()
                .skip(checkpoint.sender_index)
                .copied()
                .collect();
            Ok(PullResponse {
                checkpoint: Checkpoint::new(
                    into_array_unchecked(
                        ledger
                            .utxo_forest
                            .forest
                            .as_ref()
                            .iter()
                            .map(move |t| t.len())
                            .collect::<Vec<_>>(),
                    ),
                    ledger.void_numbers.len(),
                ),
                receivers,
                senders,
            })
        })
    }

    #[inline]
    fn push(&mut self, posts: Vec<TransferPost>) -> LocalBoxFuture<PushResult<Config, Self>> {
        Box::pin(async {
            let mut ledger = self.ledger.write().await;
            for post in posts {
                let (sources, sinks) = match TransferShape::from_post(&post) {
                    Some(TransferShape::Mint) => (vec![self.account], vec![]),
                    Some(TransferShape::PrivateTransfer) => (vec![], vec![]),
                    Some(TransferShape::Reclaim) => (vec![], vec![self.account]),
                    _ => return Ok(PushResponse { success: false }),
                };
                match post.validate(sources, sinks, &*ledger) {
                    Ok(posting_key) => {
                        posting_key.post(&(), &mut *ledger);
                    }
                    _ => return Ok(PushResponse { success: false }),
                }
            }
            Ok(PushResponse { success: true })
        })
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        config::FullParameters,
        key::{Language, Mnemonic, TestnetKeySecret},
        wallet::{self, cache::OnDiskMultiProvingContext, Signer, Wallet},
    };
    use async_std::task;
    use manta_accounting::{
        asset::Asset,
        key::{AccountTable, HierarchicalKeyDerivationScheme},
        transfer::{self, canonical::Transaction},
    };
    use manta_crypto::rand::{Rand, SeedableRng};
    use rand::thread_rng;
    use rand_chacha::ChaCha20Rng;

    ///
    #[async_std::test]
    async fn test() {
        let directory = task::spawn_blocking(tempfile::tempdir)
            .await
            .expect("Unable to generate temporary test directory.");
        async_std::println!("Temporary Directory: {:?}", directory).await;

        let mut rng = thread_rng();
        let parameters = rng.gen();
        let utxo_set_parameters = rng.gen();

        let (proving_context, verifying_context) = transfer::canonical::generate_context(
            &(),
            FullParameters::new(&parameters, &utxo_set_parameters),
            &mut rng,
        )
        .expect("Failed to generate contexts.");

        let cache = OnDiskMultiProvingContext::new(directory.path());
        cache
            .save(proving_context)
            .await
            .expect("Unable to save proving context to disk.");

        let mut ledger = Ledger::new(utxo_set_parameters.clone(), verifying_context);
        ledger.set_public_balance(AccountId(0), AssetId(0), AssetValue(10000));
        ledger.set_public_balance(AccountId(1), AssetId(0), AssetValue(1000));
        ledger.set_public_balance(AccountId(2), AssetId(0), AssetValue(100));

        async_std::println!("Ledger: {:?}", ledger.accounts).await;

        let ledger = Rc::new(RwLock::new(ledger));

        async_std::println!("Building Wallets").await;

        let mut alice = Wallet::empty(
            LedgerConnection::new(AccountId(0), ledger.clone()),
            Signer::new(
                AccountTable::new(
                    TestnetKeySecret::new(
                        Mnemonic::random(&mut rng, Language::English),
                        "password",
                    )
                    .map(),
                ),
                cache.clone(),
                parameters.clone(),
                wallet::UtxoSet::new(utxo_set_parameters.clone()),
                ChaCha20Rng::from_rng(&mut rng).expect("Failed to sample PRNG for signer."),
            ),
        );

        let mut bob = Wallet::empty(
            LedgerConnection::new(AccountId(1), ledger.clone()),
            Signer::new(
                AccountTable::new(
                    TestnetKeySecret::new(
                        Mnemonic::random(&mut rng, Language::English),
                        "password",
                    )
                    .map(),
                ),
                cache.clone(),
                parameters.clone(),
                wallet::UtxoSet::new(utxo_set_parameters.clone()),
                ChaCha20Rng::from_rng(&mut rng).expect("Failed to sample PRNG for signer."),
            ),
        );

        let bob_public_key = bob
            .receiving_key(Default::default())
            .await
            .expect("Unable to get Bob's public key.");

        async_std::println!("Alice [wallet]: {:?}", alice.assets()).await;
        async_std::println!("Alice [signer]: {:?}", alice.signer.state.assets).await;
        async_std::println!(
            "{:?}",
            alice
                .post(Transaction::Mint(Asset::new(AssetId(0), AssetValue(100))))
                .await
                .expect("Unable to mint.")
        )
        .await;

        alice.sync().await.expect("");

        async_std::println!("Alice [wallet]: {:?}", alice.assets()).await;
        async_std::println!("Alice [signer]: {:?}", alice.signer.state.assets).await;
        async_std::println!(
            "{:?}",
            alice
                .post(Transaction::PrivateTransfer(
                    Asset::new(AssetId(0), AssetValue(10)),
                    bob_public_key
                ))
                .await
                .expect("Unable to private transfer.")
        )
        .await;

        alice
            .sync()
            .await
            .expect("Unable to synchronise with the ledger.");
        bob.sync()
            .await
            .expect("Unable to synchronise with the ledger.");

        async_std::println!("Alice [wallet]: {:?}", alice.assets()).await;
        async_std::println!("Alice [signer]: {:?}", alice.signer.state.assets).await;
        async_std::println!("Bob [wallet]: {:?}", bob.assets()).await;
        async_std::println!("Bob [signer]: {:?}", bob.signer.state.assets).await;

        task::spawn_blocking(move || directory.close())
            .await
            .expect("Unable to delete temporary test directory.");
    }
}
