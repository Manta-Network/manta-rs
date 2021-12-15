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

use crate::transfer::{Configuration, PreSender, Receiver, Transfer, TransferPost, Utxo};
use alloc::vec;
use manta_crypto::accumulator::Accumulator;
use manta_util::{
    fallible_array_map,
    iter::{ChunkBy, IteratorExt},
    seal,
};

///
pub struct BatchRound<C, const SENDERS: usize, const RECEIVERS: usize>
where
    C: Configuration,
{
    /// PreSender Chunk Iterator
    pre_senders: ChunkBy<vec::IntoIter<PreSender<C>>, SENDERS>,

    ///
    accumulators: Vec<PreSender<C>>,

    /// Final Receiver
    receiver: Option<Receiver<C>>,
}

impl<C, const SENDERS: usize, const RECEIVERS: usize> BatchRound<C, SENDERS, RECEIVERS>
where
    C: Configuration,
{
    ///
    pub fn next_transfer<S>(&mut self, utxo_set: &mut S) -> Option<TransferPost<C>>
    where
        S: Accumulator<Item = Utxo<C>, Verifier = C::UtxoSetVerifier>,
    {
        if let Some(chunk) = self.pre_senders.next() {
            let senders =
                fallible_array_map(chunk, move |ps| ps.try_upgrade(utxo_set).ok_or(())).ok()?;

            /*
            let mut accumulator = self.signer.next_accumulator::<_, _, RECEIVERS>(
                parameters,
                asset_id,
                senders.iter().map(Sender::asset_value).sum(),
                &mut self.rng,
            )?;

            let post =
                self.build_post(Transfer::new(None, [], senders, accumulator.receivers, []))?;

            for zero in &accumulator.zeros {
                zero.as_ref().insert_utxo(utxo_set);
            }
            accumulator.pre_sender.insert_utxo(&mut self.utxo_set);

            new_zeroes.append(&mut accumulator.zeroes);
            accumulators.push(accumulator.pre_sender);
            */

            todo!()
        } else {
            /*
            accumulators.append(&mut self.pre_senders.remainder());
            self.pre_senders = accumulators.into_iter().chunk_by::<SENDERS>();
            */

            todo!()
        }
    }
}
