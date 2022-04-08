use ark_ff::{Field};
use ark_std::{One, Zero};
use crate::crypto::hash::poseidon::constants::ParamField;

impl ParamField for ark_bls12_381::Fr {
    fn zero() -> Self {
        <Self as Zero>::zero()
    }

    fn one() -> Self {
        <Self as One>::one()
    }

    fn inverse(&self) -> Option<Self> {
        <Self as Field>::inverse(self)
    }
}