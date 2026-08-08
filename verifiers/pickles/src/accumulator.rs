// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pickles recursion-accumulator verification.

use mina_curves::pasta::Vesta;
use poly_commitment::ipa::endos;

use crate::{
    format::PicklesProofPayload,
    outer::scalar_challenge_to_field,
    prepared::{vesta_point, PreparedError},
};

pub(crate) fn verify(proof: &PicklesProofPayload) -> Result<bool, PreparedError> {
    let deferred = &proof.statement.deferred_values;
    let (_, endo) = endos::<Vesta>();
    let challenges = deferred
        .bulletproof_challenges
        .map(|challenge| scalar_challenge_to_field(challenge, endo));
    let commitment = vesta_point(
        &proof
            .statement
            .messages_for_next_wrap_proof
            .challenge_polynomial_commitment,
    )?;
    native::vesta::vesta16_accumulator_check(commitment, &challenges)
        .map_err(|_| PreparedError::Evaluation)
}
