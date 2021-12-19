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

//! Batched Transfers

use crate::{
    asset::{Asset, AssetId, AssetValue},
    transfer::{
        Configuration, Parameters, PreSender, ProofSystemError, Receiver, ReceivingKey, Sender,
        SpendingKey, Transfer, TransferPost, Utxo,
    },
};
use alloc::vec;
use core::mem;
use manta_crypto::{
    accumulator::Accumulator,
    rand::{CryptoRng, Rand, RngCore},
};
use manta_util::{
    fallible_array_map, into_array_unchecked,
    iter::{ChunkBy, IteratorExt},
};

/// Secret Transfer
pub type SecretTransfer<C, const SENDERS: usize, const RECEIVERS: usize> =
    Transfer<C, 0, { SENDERS }, { RECEIVERS }, 0>;

/// Zero Coin Pre-Sender
pub struct Zero<C, K>
where
    C: Configuration,
{
    /// Spend Access Key
    key: K,

    /// Pre-Sender
    pre_sender: PreSender<C>,
}

/// Batch Join Structure
pub struct Join<C, K, const RECEIVERS: usize>
where
    C: Configuration,
{
    /// Receivers
    receivers: [Receiver<C>; RECEIVERS],

    /// Zero Coin Pre-Senders
    zeroes: Vec<Zero<C, K>>,

    /// Accumulated Balance Pre-Sender
    pre_sender: PreSender<C>,
}

impl<C, K, const RECEIVERS: usize> Join<C, K, RECEIVERS>
where
    C: Configuration,
    K: Clone,
{
    ///
    #[inline]
    pub fn new<R>(
        parameters: &Parameters<C>,
        asset: Asset,
        spending_key: &SpendingKey<C>,
        zero_key: K,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut receivers = Vec::with_capacity(RECEIVERS);
        let mut zeroes = Vec::with_capacity(RECEIVERS - 1);
        for _ in 0..RECEIVERS - 2 {
            let (receiver, pre_sender) = spending_key.internal_zero_pair(
                &parameters.ephemeral_key_commitment_scheme,
                &parameters.commitment_scheme,
                rng.gen(),
                asset.id,
            );
            receivers.push(receiver);
            zeroes.push(Zero {
                key: zero_key.clone(),
                pre_sender,
            });
        }
        let (receiver, pre_sender) = spending_key.internal_pair(
            &parameters.ephemeral_key_commitment_scheme,
            &parameters.commitment_scheme,
            rng.gen(),
            asset,
        );
        receivers.push(receiver);
        Self {
            receivers: into_array_unchecked(receivers),
            zeroes,
            pre_sender,
        }
    }
}

///
pub trait Batcher<C>
where
    C: Configuration,
{
    ///
    type UtxoSet: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>;

    ///
    type Rng: CryptoRng + RngCore + ?Sized;

    ///
    fn utxo_set(&mut self) -> &mut Self::UtxoSet;

    ///
    fn rng(&mut self) -> &mut Self::Rng;

    ///
    fn prove<const SENDERS: usize, const RECEIVERS: usize>(
        &mut self,
        transfer: SecretTransfer<C, SENDERS, RECEIVERS>,
    ) -> Result<TransferPost<C>, ProofSystemError<C>>;
}

/// Batching Error
pub enum Error<C>
where
    C: Configuration,
{
    /// Missing UTXO Membership Proof
    MissingUtxoMembershipProof,

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),
}

///
pub struct BatchRound<C, const SENDERS: usize, const RECEIVERS: usize>
where
    C: Configuration,
{
    /// Pre-Sender Chunk Iterator
    pre_senders: ChunkBy<vec::IntoIter<PreSender<C>>, SENDERS>,

    /// Joined Pre-Senders
    joins: Vec<PreSender<C>>,
}

impl<C, const SENDERS: usize, const RECEIVERS: usize> BatchRound<C, SENDERS, RECEIVERS>
where
    C: Configuration,
{
    ///
    #[inline]
    pub fn next<K, R, S, P>(
        &mut self,
        parameters: &Parameters<C>,
        spending_key: &SpendingKey<C>,
        zero_key: K,
        asset_id: AssetId,
        zeroes: &mut Vec<Zero<C, K>>,
        utxo_set: &mut S,
        mut prover: P,
        rng: &mut R,
    ) -> Result<TransferPost<C>, Error<C>>
    where
        K: Clone,
        R: CryptoRng + RngCore + ?Sized,
        S: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
        P: FnMut(
            SecretTransfer<C, SENDERS, RECEIVERS>,
        ) -> Result<TransferPost<C>, ProofSystemError<C>>,
    {
        if let Some(chunk) = self.pre_senders.next() {
            let senders = fallible_array_map(chunk, |ps| {
                ps.try_upgrade(utxo_set)
                    .ok_or(Error::MissingUtxoMembershipProof)
            })?;

            let mut join = Join::new(
                parameters,
                asset_id.with(senders.iter().map(Sender::asset_value).sum()),
                spending_key,
                zero_key,
                rng,
            );

            let post = prover(Transfer::new(None, [], senders, join.receivers, []))
                .map_err(Error::ProofSystemError)?;

            for zero in &join.zeroes {
                zero.pre_sender.insert_utxo(utxo_set);
            }
            join.pre_sender.insert_utxo(utxo_set);

            zeroes.append(&mut join.zeroes);
            self.joins.push(join.pre_sender);

            Ok(post)
        } else {
            /*
            self.joins.append(&mut self.pre_senders.remainder());
            self.pre_senders = mem::take(&mut self.joins).into_iter().chunk_by::<SENDERS>();
            */

            todo!()
        }
    }
}
