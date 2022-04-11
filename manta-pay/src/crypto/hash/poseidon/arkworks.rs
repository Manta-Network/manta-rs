use crate::crypto::hash::poseidon::constants::ParamField;
use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
use ark_std::{One, Zero};

impl ParamField for ark_bls12_381::Fr {
    const MODULUS_BITS: usize = <Self as PrimeField>::Params::MODULUS_BITS as usize;

    fn zero() -> Self {
        <Self as Zero>::zero()
    }

    fn one() -> Self {
        <Self as One>::one()
    }

    fn inverse(&self) -> Option<Self> {
        <Self as Field>::inverse(self)
    }

    fn try_from_bits_le(bits: &[bool]) -> Option<Self> {
        let bigint = <Self as PrimeField>::BigInt::from_bits_le(&bits);
        Self::from_repr(bigint)
    }

    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        <Self as PrimeField>::from_le_bytes_mod_order(bytes)
    }
}
