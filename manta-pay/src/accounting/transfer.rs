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

//! Transfer Implementations

use crate::accounting::config::Configuration;
use manta_accounting::transfer::{self as transfer, canonical};

/// Mint Transaction Type
pub type Mint = canonical::Mint<Configuration>;

/// Private Transfer Transaction Type
pub type PrivateTransfer = canonical::PrivateTransfer<Configuration>;

/// Reclaim Transaction Type
pub type Reclaim = canonical::Reclaim<Configuration>;

/// Transfer Post Type
pub type TransferPost = transfer::TransferPost<Configuration>;

/// Testing Suite
#[cfg(test)]
mod test {
    use crate::accounting::{
        config,
        identity::UtxoSet,
        transfer::{Mint, PrivateTransfer, Reclaim},
    };
    use manta_crypto::{
        constraint::{measure::Measure, ProofSystem},
        rand::Rand,
    };
    use rand::thread_rng;

    /// Tests the generation of proving/verifying contexts for [`Mint`].
    #[test]
    fn sample_mint_context() {
        let mut rng = thread_rng();
        let cs = Mint::sample_unknown_constraints(&mut rng);
        println!("Mint: {:?}", cs.measure());
        config::ProofSystem::generate_context(cs, &mut rng).unwrap();
    }

    /// Tests the generation of proving/verifying contexts for [`PrivateTransfer`].
    #[test]
    fn sample_private_transfer_context() {
        let mut rng = thread_rng();
        let cs = PrivateTransfer::sample_unknown_constraints(&mut rng);
        println!("PrivateTransfer: {:?}", cs.measure());
        config::ProofSystem::generate_context(cs, &mut rng).unwrap();
    }

    /// Tests the generation of proving/verifying contexts for [`Reclaim`].
    #[test]
    fn sample_reclaim_context() {
        let mut rng = thread_rng();
        let cs = Reclaim::sample_unknown_constraints(&mut rng);
        println!("Reclaim: {:?}", cs.measure());
        config::ProofSystem::generate_context(cs, &mut rng).unwrap();
    }

    /// Tests the generation of a [`Mint`].
    #[test]
    fn mint() {
        let mut rng = thread_rng();
        assert!(matches!(
            Mint::sample_and_check_proof(&rng.gen(), &mut UtxoSet::new(rng.gen()), &mut rng),
            Ok(true)
        ));
    }

    /// Tests the generation of a [`PrivateTransfer`].
    #[test]
    fn private_transfer() {
        let mut rng = thread_rng();
        assert!(matches!(
            PrivateTransfer::sample_and_check_proof(
                &rng.gen(),
                &mut UtxoSet::new(rng.gen()),
                &mut rng
            ),
            Ok(true)
        ));
    }

    /// Tests the generation of a [`Reclaim`].
    #[test]
    fn reclaim() {
        let mut rng = thread_rng();
        assert!(matches!(
            Reclaim::sample_and_check_proof(&rng.gen(), &mut UtxoSet::new(rng.gen()), &mut rng),
            Ok(true)
        ));
    }
}
