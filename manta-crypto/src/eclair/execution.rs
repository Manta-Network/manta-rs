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

//! Execution Engines

use crate::rand::RngCore;

/// Execution Engine
pub trait Engine<COM> {
    /// Engine Output Type
    type Output;

    /// Error Type
    type Error;

    /// Initializes a compiler that will be used to construct execution information.
    fn init(&self) -> COM;

    /// Finalizes the exectution with `compiler` producing [`Output`](Self::Output).
    fn finalize<R>(&self, compiler: COM, rng: &mut R) -> Result<Self::Output, Self::Error>
    where
        R: RngCore + ?Sized;
}

/// Proof System
pub trait ProofSystem {
    /// Base Compiler
    type Compiler;

    /// Proving Context
    type ProvingContext;

    /// Verifying Context
    type VerifyingContext;

    /// Context Generation Engine
    type ContextEngine: Engine<
        Self::Compiler,
        Output = (Self::ProvingContext, Self::VerifyingContext),
    >;

    /// Proof
    type Proof;

    /// Proof Engine
    type ProofEngine: Engine<Self::Compiler, Output = Self::Proof>;

    /// Public Input
    type Input;

    /// Verification Error
    type Error;

    /// Verifies that `proof` with `input` is valid with respect to the [`ContextEngine`] and
    /// [`ProofEngine`] for this proof system.
    ///
    /// [`ContextEngine`]: Self::ContextEngine
    /// [`ProofEngine`]: Self::ProofEngine
    fn verify(
        context: &Self::VerifyingContext,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error>;
}
