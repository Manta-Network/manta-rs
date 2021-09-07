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

//! Wallet Abstractions

use crate::{
    account::{Sender, ShieldedIdentity, VoidNumberCommitment},
    asset::{Asset, AssetBalance, AssetId},
    ledger::Ledger,
    transfer::{SecretTransfer, SecretTransferConfiguration},
};
use core::convert::Infallible;
use manta_crypto::ConcatBytes;

/// Asset Map
pub trait AssetMap {
    /// Returns the current balance associated with this `id`.
    fn balance(&self, id: AssetId) -> AssetBalance;

    /// Returns `true` if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    fn contains(&self, asset: Asset) -> bool {
        self.balance(asset.id) >= asset.value
    }

    /// Sets the asset balance for `id` to `value`.
    fn set_balance(&mut self, id: AssetId, value: AssetBalance);

    /// Sets the asset balance for `asset.id` to `asset.value`.
    #[inline]
    fn set_asset(&mut self, asset: Asset) {
        self.set_balance(asset.id, asset.value)
    }

    /// Mutates the asset balance for `id` to the result of `f` if it succeeds.
    #[inline]
    #[must_use = "this only modifies the stored value if the function call succeeded"]
    fn mutate<F, E>(&mut self, id: AssetId, f: F) -> Result<AssetBalance, E>
    where
        F: FnOnce(AssetBalance) -> Result<AssetBalance, E>,
    {
        // TODO: use `try_trait_v2` when it comes out
        f(self.balance(id)).map(move |v| {
            self.set_balance(id, v);
            v
        })
    }

    /// Performs a deposit of value `asset.value` into the balance of `asset.id`,
    /// returning the new balance for this `asset.id` if it did not overflow.
    ///
    /// To skip the overflow check, use [`deposit_unchecked`](Self::deposit_unchecked) instead.
    #[inline]
    #[must_use = "this only modifies the stored value if the addition did not overflow"]
    fn deposit(&mut self, asset: Asset) -> Option<AssetBalance> {
        self.mutate(asset.id, move |v| v.checked_add(asset.value).ok_or(()))
            .ok()
    }

    /// Performs a deposit of value `asset.value` into the balance of `asset.id`,
    /// without checking for overflow, returning the new balance for this `asset.id`.
    ///
    /// # Panics
    ///
    /// This function panics on overflow. To explicitly check for overflow, use
    /// [`deposit`](Self::deposit) instead.
    #[inline]
    fn deposit_unchecked(&mut self, asset: Asset) -> AssetBalance {
        self.mutate::<_, Infallible>(asset.id, move |v| Ok(v + asset.value))
            .unwrap()
    }

    /// Performs a withdrawl of value `asset.value` from the balance of `asset.id`,
    /// returning the new balance for this `asset.id` if it did not overflow.
    ///
    /// To skip the overflow check, use [`withdraw_unchecked`](Self::withdraw_unchecked) instead.
    #[inline]
    #[must_use = "this only modifies the stored value if the subtraction did not overflow"]
    fn withdraw(&mut self, asset: Asset) -> Option<AssetBalance> {
        self.mutate(asset.id, move |v| v.checked_sub(asset.value).ok_or(()))
            .ok()
    }

    /// Performs a withdrawl of value `asset.value` from the balance of `asset.id`,
    /// without checking for overflow, returning the new balance for this `asset.id`.
    ///
    /// # Panics
    ///
    /// This function panics on overflow. To explicitly check for overflow, use
    /// [`withdraw`](Self::withdraw) instead.
    #[inline]
    fn withdraw_unchecked(&mut self, asset: Asset) -> AssetBalance {
        self.mutate::<_, Infallible>(asset.id, move |v| Ok(v - asset.value))
            .unwrap()
    }
}

/// Wallet
pub struct Wallet<T, M>
where
    T: SecretTransferConfiguration,
    M: AssetMap,
{
    /// Secret Key Source
    secret_key_source: T::SecretKeyGenerator,

    /// Public Asset Map
    public_assets: M,

    /// Secret Asset Map
    secret_assets: M,
}

impl<T, M> Wallet<T, M>
where
    T: SecretTransferConfiguration,
    M: AssetMap,
{
    /// Builds a new [`Wallet`] from a `secret_key_source`.
    #[inline]
    pub fn new(secret_key_source: T::SecretKeyGenerator) -> Self
    where
        M: Default,
    {
        Self::with_balances(secret_key_source, Default::default(), Default::default())
    }

    /// Builds a new [`Wallet`] from a `secret_key_source` and pre-built
    /// `public_assets` map and `secret_assets` map.
    #[inline]
    pub fn with_balances(
        secret_key_source: T::SecretKeyGenerator,
        public_assets: M,
        secret_assets: M,
    ) -> Self {
        Self {
            secret_key_source,
            public_assets,
            secret_assets,
        }
    }

    /// Updates `self` with new information from the ledger.
    pub fn pull_updates<L>(&mut self, ledger: &L)
    where
        L: Ledger,
    {
        // TODO: pull updates from the ledger
        //         - new void numbers?
        //         - new utxos?
        //         - new encrypted notes?
        let _ = ledger;
        todo!()
    }

    /// Builds a [`SecretTransfer`] transaction to send `asset` to `receiver`.
    pub fn secret_send(
        &self,
        commitment_scheme: &T::CommitmentScheme,
        asset: Asset,
        receiver: ShieldedIdentity<T, T::IntegratedEncryptionScheme>,
    ) -> Option<SecretTransfer<T, 2, 2>>
    where
        VoidNumberCommitment<T>: ConcatBytes,
    {
        // TODO: spec:
        // 1. check that we have enough `asset` in the secret_assets map
        // 2. find out which keys have control over `asset`
        // 3. build two senders and build a receiver and a change receiver for the extra change

        // TODO: which `rng` do we use for the receivers?

        /*
        let sender = Sender::generate(self.secret_key_source, commitment_scheme);
        let receiver = receiver.into_receiver(commitment_scheme, asset, rng);
        */
        let _ = (commitment_scheme, asset, receiver);
        todo!()
    }
}
