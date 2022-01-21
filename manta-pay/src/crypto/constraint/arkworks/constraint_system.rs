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

//! Arkworks Constraint System Implementation

use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, select::CondSelectGadget};
use ark_relations::{ns, r1cs as ark_r1cs};
use manta_crypto::{
    constraint::{
        measure::Measure, Add, ConditionalSelect, Constant, ConstraintSystem, Equal, Public,
        Secret, Variable,
    },
    rand::{CryptoRng, RngCore, Sample, Standard},
};
use scale_codec::{Decode, Encode, EncodeLike};

pub use ark_r1cs::SynthesisError;
pub use ark_r1cs_std::{bits::boolean::Boolean, fields::fp::FpVar};

/// Prime Field Element
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Fp<F>(pub F)
where
    F: PrimeField;

impl<F> Decode for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
    where
        I: scale_codec::Input,
    {
        Ok(Self(
            F::deserialize(codec::ScaleCodecReader(input)).map_err(|_| "Deserialization Error")?,
        ))
    }
}

impl<F> Encode for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        let mut buffer = Vec::new();
        self.0
            .serialize(&mut buffer)
            .expect("Encoding is not allowed to fail.");
        f(&buffer)
    }
}

impl<F> EncodeLike for Fp<F> where F: PrimeField {}

impl<F> Sample for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        Self(F::rand(rng))
    }
}

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

/// Returns an empty variable assignment for setup mode.
///
/// # Warning
///
/// This does not work for all variable assignments! For some assignemnts, the variable inherits
/// some structure from its input, like its length or number of bits, which are only known at
/// run-time. For those cases, some mocking is required and this function can not be used directly.
#[inline]
pub fn empty<T>() -> SynthesisResult<T> {
    Err(SynthesisError::AssignmentMissing)
}

/// Returns a filled variable assignment with the given `value`.
#[inline]
pub fn full<T>(value: T) -> impl FnOnce() -> SynthesisResult<T> {
    move || Ok(value)
}

/// Arkworks Rank-1 Constraint System
pub struct R1CS<F>
where
    F: PrimeField,
{
    /// Constraint System
    pub(crate) cs: ark_r1cs::ConstraintSystemRef<F>,
}

impl<F> R1CS<F>
where
    F: PrimeField,
{
    /// Constructs a new constraint system which is ready for unknown variables.
    #[inline]
    pub fn for_unknown() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ark_r1cs::ConstraintSystem::new_ref();
        cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
        cs.set_mode(ark_r1cs::SynthesisMode::Setup);
        Self { cs }
    }

    /// Constructs a new constraint system which is ready for known variables.
    #[inline]
    pub fn for_known() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ark_r1cs::ConstraintSystem::new_ref();
        cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
        Self { cs }
    }
}

impl<F> ConstraintSystem for R1CS<F>
where
    F: PrimeField,
{
    type Bool = Boolean<F>;

    #[inline]
    fn assert(&mut self, b: Self::Bool) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("Enforcing equality is not allowed to fail.");
    }
}

impl<F> Measure for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn constraint_count(&self) -> usize {
        self.cs.num_constraints()
    }

    #[inline]
    fn public_variable_count(&self) -> Option<usize> {
        Some(self.cs.num_instance_variables())
    }

    #[inline]
    fn secret_variable_count(&self) -> Option<usize> {
        Some(self.cs.num_witness_variables())
    }
}

impl<F> Constant<R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.cs, "boolean constant"), this)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Public, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "boolean public input"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "boolean public input"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "boolean secret witness"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "boolean secret witness"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Equal<R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> Constant<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.cs, "field constant"), this.0)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Public, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "field public input"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "field public input"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "field secret witness"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "field secret witness"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Equal<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> ConditionalSelect<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn select(
        bit: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
        compiler: &mut R1CS<F>,
    ) -> Self {
        let _ = compiler;
        Self::conditionally_select(bit, true_value, false_value)
            .expect("Conditionally selecting from two values is not allowed to fail.")
    }
}

impl<F> Add<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn add(lhs: Self, rhs: Self, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        lhs + rhs
    }
}

/// Codec Utilities
pub mod codec {
    use ark_std::io::{self, Error, ErrorKind};
    use manta_util::codec::{Read, ReadExactError, Write};
    use scale_codec::Input;

    pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

    /// Arkworks Encoding Marker
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Ark;

    /// Scale-Codec Input as Reader Wrapper
    #[derive(Debug, Eq, Hash, PartialEq)]
    pub struct ScaleCodecReader<'i, I>(pub &'i mut I)
    where
        I: Input;

    impl<I> io::Read for ScaleCodecReader<'_, I>
    where
        I: Input,
    {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let len = buf.len();
            self.read_exact(buf).map(|_| len)
        }

        #[inline]
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            Input::read(self.0, buf).map_err(|_| ErrorKind::Other.into())
        }
    }

    /// Serialization Hook
    pub trait HasSerialization<'s>: 's {
        /// Serialize Type
        type Serialize: CanonicalSerialize + From<&'s Self>;
    }

    /// Deserialization Hook
    pub trait HasDeserialization: Sized {
        /// Deserialize Type
        type Deserialize: CanonicalDeserialize + Into<Self>;
    }

    /// Arkworks Reader
    pub struct ArkReader<R>
    where
        R: Read,
    {
        /// Reader State
        state: Result<R, R::Error>,
    }

    impl<R> ArkReader<R>
    where
        R: Read,
    {
        /// Builds a new [`ArkReader`] from `reader`.
        #[inline]
        pub fn new(reader: R) -> Self {
            Self { state: Ok(reader) }
        }

        /// Updates the internal reader state by performing the `f` computation.
        #[inline]
        fn update<T, F>(&mut self, f: F) -> Option<T>
        where
            F: FnOnce(&mut R) -> Result<T, R::Error>,
        {
            if let Ok(reader) = self.state.as_mut() {
                match f(reader) {
                    Ok(value) => return Some(value),
                    Err(err) => self.state = Err(err),
                }
            }
            None
        }

        /// Returns the reader state back or an error if it occured during any [`Read`](io::Read)
        /// methods.
        #[inline]
        pub fn finish(self) -> Result<R, R::Error> {
            self.state
        }
    }

    impl<R> io::Read for ArkReader<R>
    where
        R: Read,
    {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            self.update(|reader| reader.read(buf))
                .ok_or_else(|| Error::new(ErrorKind::Other, "Reading Error"))
        }

        #[inline]
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            match self.update(|reader| match reader.read_exact(buf) {
                Ok(value) => Ok(Ok(value)),
                Err(ReadExactError::Read(err)) => Err(err),
                Err(ReadExactError::UnexpectedEnd(err)) => Ok(Err(err)),
            }) {
                Some(Ok(_)) => Ok(()),
                Some(Err(_)) => Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "Unexpected end of buffer.",
                )),
                _ => Err(Error::new(ErrorKind::Other, "Reading Error")),
            }
        }
    }

    /// Arkworks Writer
    pub struct ArkWriter<W>
    where
        W: Write,
    {
        /// Writer State
        state: Result<W, W::Error>,
    }

    impl<W> ArkWriter<W>
    where
        W: Write,
    {
        /// Builds a new [`ArkWriter`] from `writer`.
        #[inline]
        pub fn new(writer: W) -> Self {
            Self { state: Ok(writer) }
        }

        /// Updates the internal writer state by performing the `f` computation.
        #[inline]
        fn update<T, F>(&mut self, f: F) -> Option<T>
        where
            F: FnOnce(&mut W) -> Result<T, W::Error>,
        {
            if let Ok(writer) = self.state.as_mut() {
                match f(writer) {
                    Ok(value) => return Some(value),
                    Err(err) => self.state = Err(err),
                }
            }
            None
        }

        /// Returns the writer state back or an error if it occured during any [`Write`](io::Write)
        /// methods.
        #[inline]
        pub fn finish(self) -> Result<W, W::Error> {
            self.state
        }
    }

    impl<W> io::Write for ArkWriter<W>
    where
        W: Write,
    {
        #[inline]
        fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
            self.update(|writer| writer.write(&mut buf))
                .ok_or_else(|| Error::new(ErrorKind::Other, "Writing Error"))
        }

        #[inline]
        fn flush(&mut self) -> Result<(), Error> {
            // NOTE: We can't necessarily do better than this for now, unfortunately.
            Ok(())
        }

        #[inline]
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
            let _ = self.write(buf)?;
            if buf.is_empty() {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ))
            }
        }
    }
}
