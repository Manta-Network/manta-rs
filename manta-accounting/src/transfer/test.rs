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

//! Transfer Protocol Testing Framework

use crate::transfer::{Configuration, Parameters};
use manta_crypto::rand::{CryptoRng, Rand, RngCore, Sample, Standard};

/// Parameters Distribution
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParametersDistribution<K = Standard, U = Standard, V = Standard> {
    /// Key Agreement Scheme Distribution
    pub key_agreement: K,

    /// UTXO Commitment Scheme Distribution
    pub utxo_commitment: U,

    /// Void Number Hash Function Distribution
    pub void_number_hash: V,
}

impl<K, U, V, C> Sample<ParametersDistribution<K, U, V>> for Parameters<C>
where
    C: Configuration + ?Sized,
    C::KeyAgreementScheme: Sample<K>,
    C::UtxoCommitmentScheme: Sample<U>,
    C::VoidNumberHashFunction: Sample<V>,
{
    #[inline]
    fn sample<R>(distribution: ParametersDistribution<K, U, V>, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Parameters::new(
            rng.sample(distribution.key_agreement),
            rng.sample(distribution.utxo_commitment),
            rng.sample(distribution.void_number_hash),
        )
    }
}
