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

//! Groth16 MPC

use crate::{
    groth16::kzg::{self, Accumulator},
    pairing::{Pairing, PairingEngineExt},
    ratio::{HashToGroup, RatioProof},
    util::{
        batch_into_projective, batch_mul_fixed_scalar, AffineCurve, BlakeHasher,
        CanonicalSerialize, Field, Hasher, PrimeField, ProjectiveCurve, Sample, Write, Zero,
    },
};
use alloc::{vec, vec::Vec};
use ark_ff::UniformRand;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use core::{clone::Clone, marker::PhantomData};
use manta_crypto::rand::{CryptoRng, OsRng, RngCore};
use manta_util::{cfg_into_iter, cfg_reduce};

#[cfg(feature = "rayon")]
use rayon::iter::IndexedParallelIterator;

/// Proving Key Hasher
pub trait ProvingKeyHasher<P>
where
    P: Pairing,
{
    /// Output Type
    type Output;

    /// Hashes the Groth16 `proving_key` state.
    fn hash(proving_key: &ProvingKey<P::Pairing>) -> Self::Output;
}

/// MPC State
pub type State<P> = ProvingKey<<P as Pairing>::Pairing>;

/// MPC Proof
pub type Proof<P> = RatioProof<P>;

/// MPC Error
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Too Many Constraints Error
    TooManyConstraints,

    /// Constraint System Error
    ConstraintSystemError(SynthesisError),

    /// Missing Constraint System Matrices Error
    MissingCSMatrices,

    /// Constraint System Hashes Mismatch Error
    ConstraintSystemHashesDiffer,

    /// Invalid Signature Error
    SignatureInvalid,

    /// Inconsistent Delta Change Error
    InconsistentDeltaChange,

    /// Inconsistent L Change Error
    InconsistentLChange,

    /// Inconsistent H Change Error
    InconsistentHChange,

    /// Invariant Violation Error
    InvariantViolated(&'static str),
}

/// Specialize all phase1 parameters to phase2 parameters (except `h_query`) at once. This is like
/// doing `eval_poly` in parallel on all four kinds of commitments that phase 2 param.s require
/// (`a_g1`, `b_g1`, `b_g2`, `extra`) where `extra` is the cross term that we (may wish to) compute
/// separately for public/private inputs.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn specialize_to_phase_2<G1, G2>(
    tau_basis_g1: &[G1],
    tau_basis_g2: &[G2],
    alpha_tau_basis: &[G1],
    beta_tau_basis: &[G1],
    a_poly: &[Vec<(G1::ScalarField, usize)>],
    b_poly: &[Vec<(G1::ScalarField, usize)>],
    c_poly: &[Vec<(G1::ScalarField, usize)>],
    a_g1: &mut [G1],
    b_g1: &mut [G1],
    b_g2: &mut [G2],
    ext: &mut [G1],
) where
    G1: ProjectiveCurve,
    G2: ProjectiveCurve<ScalarField = G1::ScalarField>,
{
    assert_eq!(a_g1.len(), b_g1.len());
    assert_eq!(a_g1.len(), b_g2.len());
    assert_eq!(a_g1.len(), ext.len());
    a_poly
        .iter()
        .zip(b_poly.iter())
        .zip(c_poly.iter())
        .zip(tau_basis_g1.iter())
        .zip(tau_basis_g2.iter())
        .zip(alpha_tau_basis.iter())
        .zip(beta_tau_basis.iter())
        .for_each(
            |((((((a_poly, b_poly), c_poly), tau_g1), tau_g2), alpha_tau), beta_tau)| {
                for (coeff, index) in a_poly.iter() {
                    a_g1[*index] += tau_g1.mul(coeff.into_repr());
                    ext[*index] += beta_tau.mul(coeff.into_repr());
                }
                for (coeff, index) in b_poly.iter() {
                    b_g1[*index] += tau_g1.mul(coeff.into_repr());
                    b_g2[*index] += tau_g2.mul(coeff.into_repr());
                    ext[*index] += alpha_tau.mul(coeff.into_repr());
                }
                for (coeff, index) in c_poly.iter() {
                    ext[*index] += tau_g1.mul(coeff.into_repr());
                }
            },
        );
}

/// Checks that the parameters which are not changed by contributions are the same.
#[inline]
pub fn check_invariants<P>(prev: &State<P>, next: &State<P>) -> Result<(), Error>
where
    P: Pairing,
{
    if prev.h_query.len() != next.h_query.len() {
        return Err(Error::InvariantViolated("H length changed"));
    }
    if prev.l_query.len() != next.l_query.len() {
        return Err(Error::InvariantViolated("L length changed"));
    }
    if prev.a_query != next.a_query {
        return Err(Error::InvariantViolated("A query changed"));
    }
    if prev.b_g1_query != next.b_g1_query {
        return Err(Error::InvariantViolated("B_G1 query changed"));
    }
    if prev.b_g2_query != next.b_g2_query {
        return Err(Error::InvariantViolated("B_G2 query changed"));
    }
    if prev.vk.alpha_g1 != next.vk.alpha_g1 {
        return Err(Error::InvariantViolated("alpha_G1 changed"));
    }
    if prev.beta_g1 != next.beta_g1 {
        return Err(Error::InvariantViolated("beta_G1 changed"));
    }
    if prev.vk.beta_g2 != next.vk.beta_g2 {
        return Err(Error::InvariantViolated("beta_G2 changed"));
    }
    if prev.vk.gamma_g2 != next.vk.gamma_g2 {
        return Err(Error::InvariantViolated("gamma_G2 changed"));
    }
    if prev.vk.gamma_abc_g1 != next.vk.gamma_abc_g1 {
        return Err(Error::InvariantViolated("Public input cross terms changed"));
    }
    Ok(())
}

/// Compress two vectors of curve points into a pair of curve points by random linear combination.
/// The same random linear combination is used for both vectors, allowing this pair to be used in a
/// consistent ratio test.
#[inline]
pub fn random_linear_combinations<P>(lhs: &[P::G1], rhs: &[P::G1]) -> (P::G1, P::G1)
where
    P: Pairing,
{
    assert_eq!(lhs.len(), rhs.len());
    cfg_reduce!(
        cfg_into_iter!(0..lhs.len())
            .map(|_| {
                let mut rng = OsRng;
                P::Scalar::rand(&mut rng)
            })
            .zip(lhs)
            .zip(rhs)
            .map(|((rho, lhs), rhs)| (lhs.mul(rho).into_affine(), rhs.mul(rho).into_affine())),
        || (Zero::zero(), Zero::zero()),
        |mut acc, next| {
            acc.0 = acc.0 + next.0;
            acc.1 = acc.1 + next.1;
            acc
        }
    )
}

/// Initialize [`State`] using the KZG accumulator `powers` and the given `constraint_system`.
#[inline]
pub fn initialize<C, S>(powers: Accumulator<C>, constraint_system: S) -> Result<State<C>, Error>
where
    C: kzg::Configuration,
    S: ConstraintSynthesizer<C::Scalar>,
{
    let constraints = ConstraintSystem::new_ref();
    constraint_system
        .generate_constraints(constraints.clone())
        .map_err(Error::ConstraintSystemError)?;
    constraints.finalize();
    let num_constraints = constraints.num_constraints();
    let num_instance_variables = constraints.num_instance_variables();
    let domain = match Radix2EvaluationDomain::new(num_constraints + num_instance_variables) {
        Some(domain) => domain,
        None => return Err(Error::TooManyConstraints),
    };
    let constraint_matrices = match constraints.to_matrices() {
        Some(matrices) => matrices,
        None => return Err(Error::MissingCSMatrices),
    };
    let beta_g1 = powers.beta_tau_powers_g1[0];
    let degree = domain.size as usize;
    let mut h_query = Vec::with_capacity(degree - 1);
    for i in 0..degree {
        let tmp = powers.tau_powers_g1[i + degree].into_projective();
        let tmp2 = powers.tau_powers_g1[i].into_projective();
        h_query.push((tmp - tmp2).into_affine());
    }
    let tau_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.tau_powers_g1));
    let tau_lagrange_g2 = domain.ifft(&batch_into_projective(&powers.tau_powers_g2));
    let alpha_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.alpha_tau_powers_g1));
    let beta_lagrange_g1 = domain.ifft(&batch_into_projective(&powers.beta_tau_powers_g1));
    let num_witnesses =
        constraint_matrices.num_witness_variables + constraint_matrices.num_instance_variables;
    let mut a_g1 = vec![C::G1::zero().into_projective(); num_witnesses];
    let mut b_g1 = vec![C::G1::zero().into_projective(); num_witnesses];
    let mut b_g2 = vec![C::G2::zero().into_projective(); num_witnesses];
    let mut ext = vec![C::G1::zero().into_projective(); num_witnesses];
    {
        let start = 0;
        let end = num_instance_variables;
        a_g1[start..end]
            .copy_from_slice(&tau_lagrange_g1[(start + num_constraints)..(end + num_constraints)]);
        ext[start..end]
            .copy_from_slice(&beta_lagrange_g1[(start + num_constraints)..(end + num_constraints)]);
    }
    specialize_to_phase_2(
        &tau_lagrange_g1,
        &tau_lagrange_g2,
        &alpha_lagrange_g1,
        &beta_lagrange_g1,
        &constraint_matrices.a,
        &constraint_matrices.b,
        &constraint_matrices.c,
        &mut a_g1,
        &mut b_g1,
        &mut b_g2,
        &mut ext,
    );
    let a_query = ProjectiveCurve::batch_normalization_into_affine(&a_g1);
    let b_g1_query = ProjectiveCurve::batch_normalization_into_affine(&b_g1);
    let b_g2_query = ProjectiveCurve::batch_normalization_into_affine(&b_g2);
    let ext = ProjectiveCurve::batch_normalization_into_affine(&ext);
    let public_cross_terms = Vec::from(&ext[..constraint_matrices.num_instance_variables]);
    let private_cross_terms = Vec::from(&ext[constraint_matrices.num_instance_variables..]);
    let vk = VerifyingKey {
        alpha_g1: powers.alpha_tau_powers_g1[0],
        beta_g2: powers.beta_g2,
        gamma_g2: C::g2_prime_subgroup_generator(),
        delta_g2: C::g2_prime_subgroup_generator(),
        gamma_abc_g1: public_cross_terms,
    };
    Ok(ProvingKey {
        vk,
        beta_g1,
        delta_g1: C::g1_prime_subgroup_generator(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query: private_cross_terms,
    })
}

///
pub trait Configuration: Pairing {
    ///
    type Challenge;

    ///
    type Hasher: Default + HashToGroup<Self, Self::Challenge>;

    ///
    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge;
}

///
#[inline]
pub fn contribute<C, R>(
    hasher: &C::Hasher,
    challenge: &C::Challenge,
    state: &mut State<C>,
    rng: &mut R,
) -> Option<Proof<C>>
where
    C: Configuration,
    R: CryptoRng + RngCore + ?Sized,
{
    let delta = C::Scalar::rand(rng);
    let delta_inverse = match delta.inverse() {
        Some(delta_inverse) => delta_inverse,
        _ => return None,
    };
    batch_mul_fixed_scalar(&mut state.l_query, delta_inverse);
    batch_mul_fixed_scalar(&mut state.h_query, delta_inverse);
    state.delta_g1 = state.delta_g1.mul(delta).into_affine();
    state.vk.delta_g2 = state.vk.delta_g2.mul(delta).into_affine();
    Proof::prove(hasher, challenge, &delta, rng)
}

///
#[inline]
pub fn verify_transform<C>(
    challenge: &C::Challenge,
    prev: State<C>,
    next: State<C>,
    proof: Proof<C>,
) -> Result<(C::Challenge, State<C>), Error>
where
    C: Configuration,
{
    check_invariants::<C>(&prev, &next)?;
    let next_challenge = C::challenge(challenge, &prev, &next, &proof);
    let ((ratio_0, ratio_1), _) = proof
        .verify(&C::Hasher::default(), challenge)
        .ok_or(Error::InconsistentDeltaChange)?;
    if !C::Pairing::same_ratio((ratio_0, ratio_1), (prev.vk.delta_g2, next.vk.delta_g2)) {
        return Err(Error::InconsistentHChange);
    }
    if !C::Pairing::same_ratio(
        (prev.delta_g1, next.delta_g1),
        (prev.vk.delta_g2, next.vk.delta_g2),
    ) {
        return Err(Error::InconsistentHChange);
    }
    if !C::Pairing::same_ratio(
        random_linear_combinations::<C>(&next.h_query, &prev.h_query),
        (prev.vk.delta_g2, next.vk.delta_g2),
    ) {
        return Err(Error::InconsistentHChange);
    }
    if !C::Pairing::same_ratio(
        random_linear_combinations::<C>(&next.l_query, &prev.l_query),
        (prev.vk.delta_g2, next.vk.delta_g2),
    ) {
        return Err(Error::InconsistentLChange);
    }
    Ok((next_challenge, next))
}

/*

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        groth16::kzg::{Contribution, Size},
        util::{
            into_array_unchecked, BlakeHasher, HasDistribution, PairingEngine, PhaseOneHashToGroup,
        },
    };
    use ark_bls12_381::{Fr, FrParameters};
    use ark_ff::{field_new, Fp256};
    use ark_groth16::Groth16 as ArkGroth16;
    use ark_r1cs_std::eq::EqGadget;
    use ark_snark::SNARK;
    use manta_crypto::{
        constraint::Allocate,
        eclair::alloc::mode::{Public, Secret},
    };
    use manta_pay::crypto::constraint::arkworks::{Fp, FpVar, R1CS};

    /// Test MPC
    #[derive(Clone, Default)]
    pub struct Test;

    impl Size for Test {
        const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
        const G2_POWERS: usize = 1 << 3;
    }

    impl HasDistribution for Test {
        type Distribution = ();
    }

    impl Pairing for Test {
        type Scalar = ark_bls12_381::Fr;
        type G1 = ark_bls12_381::G1Affine;
        type G1Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Prepared;
        type G2 = ark_bls12_381::G2Affine;
        type G2Prepared = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Prepared;
        type Pairing = ark_bls12_381::Bls12_381;

        fn g1_prime_subgroup_generator() -> Self::G1 {
            ark_bls12_381::G1Affine::prime_subgroup_generator()
        }

        fn g2_prime_subgroup_generator() -> Self::G2 {
            ark_bls12_381::G2Affine::prime_subgroup_generator()
        }
    }

    impl kzg::Configuration for Test {
        type DomainTag = u8;
        type Challenge = [u8; 64];
        type Response = [u8; 64];
        type Distribution = ();
        type HashToGroup = PhaseOneHashToGroup<Self, 64>;
        const TAU_DOMAIN_TAG: Self::DomainTag = 0;
        const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
        const BETA_DOMAIN_TAG: Self::DomainTag = 2;

        fn response(
            state: &Accumulator<Self>,
            challenge: &Self::Challenge,
            proof: &crate::groth16::kzg::Proof<Self>,
        ) -> Self::Response {
            let mut hasher = BlakeHasher::default();
            for item in &state.tau_powers_g1 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            for item in &state.tau_powers_g2 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            for item in &state.alpha_tau_powers_g1 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            for item in &state.beta_tau_powers_g1 {
                item.serialize_uncompressed(&mut hasher).unwrap();
            }
            state.beta_g2.serialize_uncompressed(&mut hasher).unwrap();
            hasher.update(&challenge);
            proof
                .tau
                .ratio
                .0
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .tau
                .ratio
                .1
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .tau
                .matching_point
                .serialize_uncompressed(&mut hasher)
                .unwrap();

            proof
                .alpha
                .ratio
                .0
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .alpha
                .ratio
                .1
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .alpha
                .matching_point
                .serialize_uncompressed(&mut hasher)
                .unwrap();

            proof
                .beta
                .ratio
                .0
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .beta
                .ratio
                .1
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            proof
                .beta
                .matching_point
                .serialize_uncompressed(&mut hasher)
                .unwrap();
            into_array_unchecked(hasher.finalize())
        }

        fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
            Self::HashToGroup { domain_tag }
        }
    }

    /// Conducts a dummy phase one trusted setup.
    pub fn dummy_phase_one_trusted_setup() -> Accumulator<Test> {
        let mut rng = OsRng;
        let accumulator = Accumulator::<Test>::default();
        let challenge = [0; 64];
        let contribution: Contribution<Test> = Contribution::gen(&mut rng);
        let proof = contribution.proof(&challenge, &mut rng).unwrap();
        let mut next_accumulator = accumulator.clone();
        next_accumulator.update(&contribution);
        Accumulator::verify_transform(accumulator, next_accumulator, challenge, proof).unwrap()
    }

    /// Generates a dummy R1CS circuit.
    pub fn dummy_circuit(cs: &mut R1CS<Fp256<FrParameters>>) {
        let a = Fp(field_new!(Fr, "2")).as_known::<Secret, FpVar<_>>(cs);
        let b = Fp(field_new!(Fr, "3")).as_known::<Secret, FpVar<_>>(cs);
        let c = &a * &b;
        let d = Fp(field_new!(Fr, "6")).as_known::<Public, FpVar<_>>(cs);
        c.enforce_equal(&d)
            .expect("enforce_equal is not allowed to fail");
    }

    /// Proves and verifies a dummy circuit with proving key `pk` and a random number generator `rng`.
    pub fn dummy_prove_and_verify_circuit<P, R>(pk: ProvingKey<P>, rng: &mut R)
    where
        P: PairingEngine<Fr = Fp256<ark_bls12_381::FrParameters>>,
        R: Rng + CryptoRng,
    {
        let mut cs = R1CS::for_proofs();
        dummy_circuit(&mut cs);
        let proof = ArkGroth16::prove(&pk, cs, rng).unwrap();
        assert!(
            ArkGroth16::verify(&pk.vk, &[field_new!(Fr, "6")], &proof).unwrap(),
            "Verify proof should succeed."
        );
    }

    /// Tests if trusted setup phase 2 is valid with trusted setup phase 1 and proves
    /// and verifies a dummy circuit.
    #[test]
    pub fn trusted_setup_phase_two_is_valid() {
        let mut rng = OsRng;
        let mut cs = R1CS::for_contexts();
        dummy_circuit(&mut cs);
        let accumulator = dummy_phase_one_trusted_setup();
        let (mut state, mut contributions) = Phase2::<Test, 64>::initialize::<
            R1CS<Fp256<ark_bls12_381::FrParameters>>,
        >(cs, accumulator.clone())
        .unwrap();
        let (mut prev_state, mut ratio_proof);
        let mut challenge = contributions.cs_hash;
        for _ in 0..5 {
            prev_state = state.clone();
            (state, ratio_proof) =
                Phase2::<Test, 64>::contribute::<_, ()>(&mut state, challenge, &mut rng);
            (state, challenge) = Phase2::<Test, 64>::verify_transform::<()>(
                challenge,
                prev_state,
                state,
                ratio_proof.clone(),
            )
            .expect("verify transform failed");
            contributions =
                Phase2::<Test, 64>::update(state.clone(), ratio_proof.clone(), contributions);
        }
        let mut cs = R1CS::for_contexts();
        dummy_circuit(&mut cs);
        Phase2::<Test, 64>::verify_transform_all::<_, ()>(
            state.clone(),
            contributions,
            cs,
            accumulator,
        )
        .expect("Verify transform all failed.");
        dummy_prove_and_verify_circuit(state.pk, &mut rng);
    }
}

*/
