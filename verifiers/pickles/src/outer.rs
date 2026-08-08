// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Conversion of the fixed Pickles wrap wire proof to Kimchi's verifier type.

use alloc::{vec, vec::Vec};

use ark_ff::Field;
use kimchi::proof::{
    PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof, RecursionChallenge,
};
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::{
    ipa::{endos, OpeningProof},
    PolyComm,
};

use crate::{
    builtin_opening::BuiltinOpeningProof,
    format::{FieldBytes, PicklesProofPayload, PointBytes, ScalarChallenge, WrapEvaluations},
    profile::decode_field,
};

pub(crate) type OuterOpeningProof = BuiltinOpeningProof;
pub(crate) type OuterProof = ProverProof<Pallas, OuterOpeningProof, FULL_ROUNDS>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OuterProofError {
    Field,
    Point,
    Recursion,
}

pub(crate) fn scalar_challenge_to_field<F>(challenge: ScalarChallenge, endo: F) -> F
where
    F: Field + From<i32>,
{
    let a = u128::from(challenge[0]);
    let b = u128::from(challenge[1]);
    let bits = (a | (b << 64)).reverse_bits();
    let one = F::one();
    let neg_one = -one;
    let mut left = F::from(2);
    let mut right = F::from(2);

    for pair in 0..64 {
        let first = ((bits >> (pair * 2 + 1)) & 1) != 0;
        let second = ((bits >> (pair * 2)) & 1) != 0;
        let sign = if first { one } else { neg_one };
        left = left.double();
        right = right.double();
        if second {
            left += sign;
        } else {
            right += sign;
        }
    }
    left * endo + right
}

pub(crate) fn pallas_point(bytes: &PointBytes) -> Result<Pallas, OuterProofError> {
    let point = Pallas::new_unchecked(
        decode_field::<Fp>(&bytes[0]).map_err(|_| OuterProofError::Point)?,
        decode_field::<Fp>(&bytes[1]).map_err(|_| OuterProofError::Point)?,
    );
    if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(OuterProofError::Point)
    }
}

fn fq(bytes: &FieldBytes) -> Result<Fq, OuterProofError> {
    decode_field(bytes).map_err(|_| OuterProofError::Field)
}

fn poly(bytes: &PointBytes) -> Result<PolyComm<Pallas>, OuterProofError> {
    Ok(PolyComm::new(vec![pallas_point(bytes)?]))
}

fn evaluation(pair: &[FieldBytes; 2]) -> Result<PointEvaluations<Vec<Fq>>, OuterProofError> {
    Ok(PointEvaluations {
        zeta: vec![fq(&pair[0])?],
        zeta_omega: vec![fq(&pair[1])?],
    })
}

fn try_map_array<T, U, E, const N: usize>(
    source: &[T; N],
    map: impl Fn(&T) -> Result<U, E>,
) -> Result<[U; N], E> {
    let mapped = source.iter().map(map).collect::<Result<Vec<_>, _>>()?;
    Ok(mapped
        .try_into()
        .unwrap_or_else(|_| unreachable!("array length is preserved")))
}

fn evaluations(
    source: &WrapEvaluations,
) -> Result<ProofEvaluations<PointEvaluations<Vec<Fq>>>, OuterProofError> {
    Ok(ProofEvaluations {
        public: None,
        w: try_map_array(&source.w, evaluation)?,
        z: evaluation(&source.z)?,
        s: try_map_array(&source.s, evaluation)?,
        coefficients: try_map_array(&source.coefficients, evaluation)?,
        generic_selector: evaluation(&source.generic_selector)?,
        poseidon_selector: evaluation(&source.poseidon_selector)?,
        complete_add_selector: evaluation(&source.complete_add_selector)?,
        mul_selector: evaluation(&source.mul_selector)?,
        emul_selector: evaluation(&source.emul_selector)?,
        endomul_scalar_selector: evaluation(&source.endomul_scalar_selector)?,
        range_check0_selector: None,
        range_check1_selector: None,
        foreign_field_add_selector: None,
        foreign_field_mul_selector: None,
        xor_selector: None,
        rot_selector: None,
        lookup_aggregation: None,
        lookup_table: None,
        lookup_sorted: [None, None, None, None, None],
        runtime_lookup_table: None,
        runtime_lookup_table_selector: None,
        xor_lookup_selector: None,
        lookup_gate_lookup_selector: None,
        range_check_lookup_selector: None,
        foreign_field_mul_lookup_selector: None,
    })
}

fn padding_commitment() -> Pallas {
    let x = ark_ff::MontFp!(
        "8063668238751197448664615329057427953229339439010717262869116690340613895496"
    );
    let y = ark_ff::MontFp!(
        "2694491010813221541025626495812026140144933943906714931997499229912601205355"
    );
    Pallas::new_unchecked(x, y)
}

fn recursion_challenges(
    proof: &PicklesProofPayload,
) -> Result<Vec<RecursionChallenge<Pallas>>, OuterProofError> {
    let (_, endo) = endos::<Pallas>();
    let mut commitments = proof
        .statement
        .messages_for_next_step_proof
        .challenge_polynomial_commitments
        .iter()
        .map(pallas_point)
        .collect::<Result<Vec<_>, _>>()?;
    if commitments.len() > 2 {
        return Err(OuterProofError::Recursion);
    }
    while commitments.len() < 2 {
        commitments.insert(0, padding_commitment());
    }

    Ok(proof
        .statement
        .messages_for_next_wrap_proof
        .old_bulletproof_challenges
        .iter()
        .zip(commitments)
        .map(|(set, commitment)| {
            RecursionChallenge::new(
                set.challenges
                    .iter()
                    .map(|challenge| scalar_challenge_to_field(*challenge, endo))
                    .collect(),
                PolyComm::new(vec![commitment]),
            )
        })
        .collect())
}

pub(crate) fn convert_outer_proof(
    source: &PicklesProofPayload,
) -> Result<OuterProof, OuterProofError> {
    let proof = &source.wrap_proof;
    let lr = proof
        .opening
        .lr
        .iter()
        .map(|pair| Ok((pallas_point(&pair[0])?, pallas_point(&pair[1])?)))
        .collect::<Result<_, OuterProofError>>()?;

    Ok(OuterProof {
        commitments: ProverCommitments {
            w_comm: try_map_array(&proof.commitments.w_comm, poly)?,
            z_comm: poly(&proof.commitments.z_comm)?,
            t_comm: PolyComm::new(
                proof
                    .commitments
                    .t_comm
                    .iter()
                    .map(pallas_point)
                    .collect::<Result<_, _>>()?,
            ),
            lookup: None,
        },
        proof: BuiltinOpeningProof::from_standard(OpeningProof {
            lr,
            delta: pallas_point(&proof.opening.delta)?,
            z1: fq(&proof.opening.z1)?,
            z2: fq(&proof.opening.z2)?,
            sg: pallas_point(&proof.opening.challenge_polynomial_commitment)?,
        }),
        evals: evaluations(&proof.evaluations)?,
        ft_eval1: fq(&proof.ft_eval1)?,
        prev_challenges: recursion_challenges(source)?,
    })
}
