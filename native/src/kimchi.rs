// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use sp_runtime_interface::runtime_interface;

use crate::VerifyError;

#[runtime_interface]
pub trait KimchiVerify {
    /// Verify a Kimchi proof natively (bypasses WASM for performance).
    /// `pubs_bytes` is the flat concatenation of 32-byte compressed `Fp` field elements.
    /// `rng_seed` is a 32-byte seed for the deterministic ChaCha20 RNG.
    fn verify_proof(
        verifier_index_bytes: &[u8],
        srs_bytes: &[u8],
        proof_bytes: &[u8],
        pubs_bytes: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<(), VerifyError> {
        imp::verify_proof(
            verifier_index_bytes,
            srs_bytes,
            proof_bytes,
            pubs_bytes,
            rng_seed,
        )
    }

    /// Validate a Kimchi verification key natively.
    fn validate_key(verifier_index_bytes: &[u8], srs_bytes: &[u8]) -> Result<(), VerifyError> {
        imp::validate_key(verifier_index_bytes, srs_bytes)
    }
}

#[cfg(feature = "std")]
mod imp {
    use super::VerifyError;
    use ark_ff::MontFp;
    use ark_serialize::CanonicalDeserialize;
    use kimchi::{
        circuits::{
            constraints::FeatureFlags,
            lookup::lookups::{LookupFeatures, LookupPatterns},
            polynomials::permutation::{permutation_vanishing_polynomial, zk_w},
        },
        error::VerifyError as KimchiVerifyError,
        groupmap::BWParameters,
        linearization::expr_linearization,
        proof::ProverProof,
        verifier::verify_with_rng,
        verifier_index::VerifierIndex,
    };
    use mina_curves::pasta::{Fp, Pallas, Vesta, VestaParameters};
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        pasta::FULL_ROUNDS,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::{
        ipa::{OpeningProof, SRS as IpaSrs},
        SRS as SrsTrait,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::sync::{Arc, OnceLock};

    type NativeOpeningProof = OpeningProof<Vesta, FULL_ROUNDS>;
    type NativeProof = ProverProof<Vesta, NativeOpeningProof, FULL_ROUNDS>;
    type NativeSrs = IpaSrs<Vesta>;
    type NativeVerifierIndex = VerifierIndex<FULL_ROUNDS, Vesta, NativeSrs>;

    pub(super) fn verify_proof(
        verifier_index_bytes: &[u8],
        srs_bytes: &[u8],
        proof_bytes: &[u8],
        pubs_bytes: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<(), VerifyError> {
        let proof: NativeProof =
            bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard())
                .map(|(p, _)| p)
                .inspect_err(|e| log::debug!("Cannot decode Kimchi proof bytes: {e}"))
                .map_err(|_| VerifyError::InvalidProofData)?;

        if !pubs_bytes.len().is_multiple_of(32) {
            return Err(VerifyError::InvalidInput);
        }
        let public_input: Vec<Fp> = pubs_bytes
            .chunks_exact(32)
            .map(|chunk| {
                Fp::deserialize_compressed(chunk)
                    .inspect_err(|e| log::debug!("Cannot decode Kimchi public input: {e}"))
                    .map_err(|_| VerifyError::InvalidInput)
            })
            .collect::<Result<_, _>>()?;

        let mut verifier_index = decode_verifier_index(verifier_index_bytes)?;
        let srs = decode_srs(srs_bytes)?;
        prepare_verifier_index(&mut verifier_index, srs)?;

        let mut rng = ChaCha20Rng::from_seed(*rng_seed);
        let group_map = vesta_group_map();

        verify_with_rng::<
            FULL_ROUNDS,
            Vesta,
            DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>,
            NativeOpeningProof,
            _,
        >(&group_map, &verifier_index, &proof, &public_input, &mut rng)
        .inspect_err(|e| log::debug!("Kimchi verification failed: {e:?}"))
        .map_err(map_kimchi_error)
    }

    pub(super) fn validate_key(
        verifier_index_bytes: &[u8],
        srs_bytes: &[u8],
    ) -> Result<(), VerifyError> {
        let mut verifier_index = decode_verifier_index(verifier_index_bytes)?;
        let srs = decode_srs(srs_bytes)?;
        prepare_verifier_index(&mut verifier_index, srs)
    }

    fn decode_verifier_index(bytes: &[u8]) -> Result<NativeVerifierIndex, VerifyError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(vi, _)| vi)
            .inspect_err(|e| log::debug!("Cannot decode Kimchi verifier index: {e}"))
            .map_err(|_| VerifyError::InvalidVerificationKey)
    }

    fn decode_srs(bytes: &[u8]) -> Result<Arc<NativeSrs>, VerifyError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(srs, _)| Arc::new(srs))
            .inspect_err(|e| log::debug!("Cannot decode Kimchi SRS: {e}"))
            .map_err(|_| VerifyError::InvalidVerificationKey)
    }

    fn prepare_verifier_index(
        verifier_index: &mut NativeVerifierIndex,
        srs: Arc<NativeSrs>,
    ) -> Result<(), VerifyError> {
        if srs.max_poly_size() < verifier_index.max_poly_size {
            return Err(VerifyError::InvalidVerificationKey);
        }

        let feature_flags = compute_feature_flags(verifier_index);
        let (linearization, powers_of_alpha) = expr_linearization(Some(&feature_flags), true);
        let (endo_q, _endo_r) = poly_commitment::ipa::endos::<Pallas>();
        let domain = verifier_index.domain;
        let zk_rows = verifier_index.zk_rows;

        verifier_index.srs = srs;
        verifier_index.endo = endo_q;
        verifier_index.linearization = linearization;
        verifier_index.powers_of_alpha = powers_of_alpha;

        let w = OnceLock::new();
        w.set(zk_w(domain, zk_rows))
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        verifier_index.w = w;

        let permutation_vanishing_polynomial_m = OnceLock::new();
        permutation_vanishing_polynomial_m
            .set(permutation_vanishing_polynomial(domain, zk_rows))
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        verifier_index.permutation_vanishing_polynomial_m = permutation_vanishing_polynomial_m;

        Ok(())
    }

    fn compute_feature_flags(verifier_index: &NativeVerifierIndex) -> FeatureFlags {
        let xor = verifier_index.xor_comm.is_some();
        let range_check0 = verifier_index.range_check0_comm.is_some();
        let range_check1 = verifier_index.range_check1_comm.is_some();
        let foreign_field_add = verifier_index.foreign_field_add_comm.is_some();
        let foreign_field_mul = verifier_index.foreign_field_mul_comm.is_some();
        let rot = verifier_index.rot_comm.is_some();

        let lookup = verifier_index
            .lookup_index
            .as_ref()
            .is_some_and(|li| li.lookup_info.features.patterns.lookup);

        let runtime_tables = verifier_index
            .lookup_index
            .as_ref()
            .is_some_and(|li| li.runtime_tables_selector.is_some());

        let patterns = LookupPatterns {
            xor,
            lookup,
            range_check: range_check0 || range_check1 || rot,
            foreign_field_mul,
        };

        FeatureFlags {
            range_check0,
            range_check1,
            foreign_field_add,
            foreign_field_mul,
            xor,
            rot,
            lookup_features: LookupFeatures {
                patterns,
                joint_lookup_used: patterns.joint_lookups_used(),
                uses_runtime_tables: runtime_tables,
            },
        }
    }

    fn vesta_group_map() -> BWParameters<VestaParameters> {
        BWParameters {
            u: MontFp!("1"),
            fu: MontFp!("6"),
            sqrt_neg_three_u_squared_minus_u_over_2: MontFp!(
                "2942865608506852014473558576493638302197734138389222805617480874486368177743"
            ),
            sqrt_neg_three_u_squared: MontFp!(
                "5885731217013704028947117152987276604395468276778445611234961748972736355487"
            ),
            inv_three_u_squared: MontFp!(
                "19298681539552699237261830834781317975575370987961098253119828498928908632065"
            ),
        }
    }

    fn map_kimchi_error(error: KimchiVerifyError) -> VerifyError {
        match error {
            KimchiVerifyError::IncorrectPubicInputLength(_) => VerifyError::InvalidInput,
            KimchiVerifyError::IncorrectCommitmentLength(_, _, _)
            | KimchiVerifyError::IncorrectPrevChallengesLength(_, _)
            | KimchiVerifyError::IncorrectEvaluationsLength(_, _, _)
            | KimchiVerifyError::LookupCommitmentMissing
            | KimchiVerifyError::LookupEvalsMissing
            | KimchiVerifyError::ProofInconsistentLookup
            | KimchiVerifyError::IncorrectRuntimeProof
            | KimchiVerifyError::MissingEvaluation(_)
            | KimchiVerifyError::MissingPublicInputEvaluation
            | KimchiVerifyError::MissingCommitment(_) => VerifyError::InvalidProofData,
            KimchiVerifyError::DifferentSRS | KimchiVerifyError::SRSTooSmall => {
                VerifyError::InvalidVerificationKey
            }
            KimchiVerifyError::OpenProof => VerifyError::VerifyError,
        }
    }
}
