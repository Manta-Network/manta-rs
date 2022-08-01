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

//! Manta-Pay UTXO Model Version 1 Configuration

use crate::crypto::constraint::arkworks::{Boolean, R1CS};
use ark_ff::PrimeField;
use core::marker::PhantomData;
use manta_crypto::eclair::Has;

pub use manta_accounting::transfer::utxo::v1 as protocol;

///
pub struct Config<COM = ()>(PhantomData<COM>);

/* TODO:
impl protocol::Configuration for Config {
    type Bool = bool;
    type AssetId = ();
    type AssetValue = ();
    type Scalar = ();
    type Group = ();
    type UtxoCommitmentScheme = ();
    type ViewingKeyDerivationFunction = ();
    type IncomingCiphertext = ();
    type IncomingBaseEncryptionScheme = ();
    type UtxoAccumulatorItemHash = ();
    type UtxoAccumulatorModel = ();
    type OutgoingCiphertext = ();
    type OutgoingBaseEncryptionScheme = ();
}
*/

/* TODO:
impl<F> protocol::Configuration<R1CS<F>> for Config<R1CS<F>>
where
    F: PrimeField,
{
    type Bool = Boolean<F>;
    type AssetId = ();
    type AssetValue = ();
    type Scalar = ();
    type Group = ();
    type UtxoCommitmentScheme = ();
    type ViewingKeyDerivationFunction = ();
    type IncomingCiphertext = ();
    type IncomingBaseEncryptionScheme = ();
    type UtxoAccumulatorItemHash = ();
    type UtxoAccumulatorModel = ();
    type OutgoingCiphertext = ();
    type OutgoingBaseEncryptionScheme = ();
}
*/
