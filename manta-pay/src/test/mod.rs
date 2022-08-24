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

//! Manta Pay Testing

// TODO: This is the old simulation. We need to integrate its features into the new asynchronous
//       simulation.
//
// #[cfg(feature = "simulation")]
// #[cfg_attr(doc_cfg, doc(cfg(feature = "simulation")))]
// pub mod simulation;

#[cfg(test)]
pub mod compatibility;

#[cfg(test)]
pub mod transfer;

#[cfg(feature = "groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "groth16")))]
pub mod payment;
