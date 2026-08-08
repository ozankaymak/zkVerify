// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Construction of the fixed Pickles wrap verifier index.

use alloc::{sync::Arc, vec, vec::Vec};
#[cfg(not(feature = "std"))]
use core::cell::OnceCell as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

use ark_ff::{BigInt, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use kimchi::{
    circuits::{
        berkeley_columns::{BerkeleyChallengeTerm, Column},
        constraints::FeatureFlags,
        expr::{ConstantTerm, Linearization, PolishToken, Variable},
        gate::{CurrOrNext, GateType},
        polynomials::permutation::{permutation_vanishing_polynomial, zk_w, Shifts},
    },
    linearization::expr_linearization,
    verifier_index::VerifierIndex,
};
use mina_curves::pasta::{Fq, Pallas, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::{ipa::endos, PolyComm, SRS};

use crate::{
    format::{PicklesVkPayload, PointBytes, ProofsVerified},
    outer::{pallas_point, OuterProofError},
    profile::{WRAP_PREV_CHALLENGES, WRAP_PUBLIC_INPUTS, WRAP_SRS_LOG2, WRAP_ZK_ROWS},
};

pub(crate) type OuterVerifierIndex<Srs> = VerifierIndex<FULL_ROUNDS, Pallas, Srs>;
type OuterToken = PolishToken<Fq, Column, BerkeleyChallengeTerm>;

include!("legacy_outer_tokens.rs");

pub(crate) fn wrap_domain_log2(size: ProofsVerified) -> u8 {
    match size {
        ProofsVerified::N0 => 13,
        ProofsVerified::N1 => 14,
        ProofsVerified::N2 => 15,
    }
}

pub(crate) fn make_verifier_index<Srs>(
    vk: &PicklesVkPayload,
    srs: Arc<Srs>,
) -> Result<OuterVerifierIndex<Srs>, OuterProofError>
where
    Srs: SRS<Pallas>,
{
    let domain_log2 = wrap_domain_log2(vk.actual_wrap_domain_size);
    let domain = D::<Fq>::new(1usize << domain_log2).ok_or(OuterProofError::Field)?;
    let feature_flags = FeatureFlags::default();
    let (_, powers_of_alpha) = expr_linearization(Some(&feature_flags), true);
    let linearization = Linearization {
        constant_term: pickles_v1_outer_linearization(),
        index_terms: Vec::new(),
    };
    let shifts = Shifts::new(&domain);
    let to_poly = |point: &PointBytes| -> Result<PolyComm<Pallas>, OuterProofError> {
        Ok(PolyComm::new(vec![pallas_point(point)?]))
    };
    let index = &vk.wrap_index;

    Ok(VerifierIndex {
        domain,
        max_poly_size: 1usize << WRAP_SRS_LOG2,
        zk_rows: WRAP_ZK_ROWS,
        srs,
        public: WRAP_PUBLIC_INPUTS,
        prev_challenges: WRAP_PREV_CHALLENGES,
        sigma_comm: try_map_array(&index.sigma_comm, to_poly)?,
        coefficients_comm: try_map_array(&index.coefficients_comm, to_poly)?,
        generic_comm: to_poly(&index.generic_comm)?,
        psm_comm: to_poly(&index.psm_comm)?,
        complete_add_comm: to_poly(&index.complete_add_comm)?,
        mul_comm: to_poly(&index.mul_comm)?,
        emul_comm: to_poly(&index.emul_comm)?,
        endomul_scalar_comm: to_poly(&index.endomul_scalar_comm)?,
        range_check0_comm: None,
        range_check1_comm: None,
        foreign_field_add_comm: None,
        foreign_field_mul_comm: None,
        xor_comm: None,
        rot_comm: None,
        shift: *shifts.shifts(),
        permutation_vanishing_polynomial_m: once(permutation_vanishing_polynomial(
            domain,
            WRAP_ZK_ROWS,
        ))?,
        w: once(zk_w(domain, WRAP_ZK_ROWS))?,
        endo: endos::<Vesta>().0,
        lookup_index: None,
        linearization,
        powers_of_alpha,
    })
}

fn outer_field(limbs: [u64; 4]) -> Fq {
    Fq::from_bigint(BigInt::new(limbs)).expect("PicklesV1 constants are canonical Fq values")
}

fn once<T>(value: T) -> Result<OnceLock<T>, OuterProofError> {
    let cell = OnceLock::new();
    cell.set(value).map_err(|_| OuterProofError::Field)?;
    Ok(cell)
}

fn try_map_array<T, U, E, const N: usize>(
    source: &[T; N],
    map: impl Fn(&T) -> Result<U, E>,
) -> Result<[U; N], E> {
    Ok(source
        .iter()
        .map(map)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .unwrap_or_else(|_| unreachable!("array length is preserved")))
}
