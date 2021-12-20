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
        CommitmentSchemeParameters, Configuration, EphemeralKeyParameters, Parameters, PreSender,
        ProofSystemError, Receiver, ReceivingKey, Sender, SpendingKey, Transfer, TransferPost,
        Utxo,
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

/// Batch Join Structure
pub struct Join<C>
where
    C: Configuration,
{
    /// Accumulated Balance Pre-Sender
    pub pre_sender: PreSender<C>,

    /// Zero Coin Pre-Senders
    pub zeroes: Vec<PreSender<C>>,
}

impl<C> Join<C>
where
    C: Configuration,
{
    /// Builds a new [`Join`] for `asset` using `spending_key` and `zero_key`.
    #[inline]
    pub fn new<R, const RECEIVERS: usize>(
        ephemeral_key_parameters: &EphemeralKeyParameters<C>,
        commitment_scheme_parameters: &CommitmentSchemeParameters<C>,
        asset: Asset,
        spending_key: &SpendingKey<C>,
        rng: &mut R,
    ) -> ([Receiver<C>; RECEIVERS], Self)
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        // TODO: Add optimization path for receiver re-sampling so that we ensure that all UTXOs
        //       are maximally independent.
        //
        let mut receivers = Vec::with_capacity(RECEIVERS);
        let mut zeroes = Vec::with_capacity(RECEIVERS - 1);
        let (receiver, pre_sender) = spending_key.internal_pair(
            ephemeral_key_parameters,
            commitment_scheme_parameters,
            rng.gen(),
            asset,
        );
        receivers.push(receiver);
        for _ in 0..RECEIVERS - 2 {
            let (receiver, pre_sender) = spending_key.internal_zero_pair(
                ephemeral_key_parameters,
                commitment_scheme_parameters,
                rng.gen(),
                asset.id,
            );
            receivers.push(receiver);
            zeroes.push(pre_sender);
        }
        (into_array_unchecked(receivers), Self { zeroes, pre_sender })
    }

    /// Inserts UTXOs for each sender in `self` into the `utxo_set` for future proof selection.
    #[inline]
    pub fn insert_utxos<A>(&self, utxo_set: &mut A)
    where
        A: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
    {
        self.pre_sender.insert_utxo(utxo_set);
        for zero in &self.zeroes {
            zero.insert_utxo(utxo_set);
        }
    }
}
