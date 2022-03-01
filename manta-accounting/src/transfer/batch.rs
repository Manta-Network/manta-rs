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

//! Batched Transfers

// TODO: Move more of the batching algorithm here to improve library interfaces.

use crate::{
    asset::Asset,
    transfer::{Configuration, Parameters, PreSender, Receiver, SpendingKey, Utxo},
};
use alloc::vec::Vec;
use manta_crypto::{
    accumulator::Accumulator,
    rand::{CryptoRng, Rand, RngCore},
};
use manta_util::into_array_unchecked;

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
        parameters: &Parameters<C>,
        asset: Asset,
        spending_key: &SpendingKey<C>,
        rng: &mut R,
    ) -> ([Receiver<C>; RECEIVERS], Self)
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut receivers = Vec::with_capacity(RECEIVERS);
        let mut zeroes = Vec::with_capacity(RECEIVERS - 1);
        let (receiver, pre_sender) = spending_key.internal_pair(parameters, rng.gen(), asset);
        receivers.push(receiver);
        for _ in 1..RECEIVERS {
            let (receiver, pre_sender) =
                spending_key.internal_zero_pair(parameters, rng.gen(), asset.id);
            receivers.push(receiver);
            zeroes.push(pre_sender);
        }
        (into_array_unchecked(receivers), Self { zeroes, pre_sender })
    }

    /// Inserts UTXOs for each sender in `self` into the `utxo_accumulator` for future proof selection.
    #[inline]
    pub fn insert_utxos<A>(&self, utxo_accumulator: &mut A)
    where
        A: Accumulator<Item = Utxo<C>, Model = C::UtxoAccumulatorModel>,
    {
        self.pre_sender.insert_utxo(utxo_accumulator);
        for zero in &self.zeroes {
            zero.insert_utxo(utxo_accumulator);
        }
    }
}
