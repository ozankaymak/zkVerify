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

#[cfg(feature = "std")]
/// Build every consensus-supported Kimchi SRS representation before block execution.
pub fn prewarm_kimchi_builtin_srs(
    srs_log2_size: u8,
    domain_log2_sizes: &[u8],
) -> Result<(), VerifyError> {
    imp::prewarm_builtin_srs(srs_log2_size, domain_log2_sizes)
}

#[runtime_interface]
pub trait KimchiVerify {
    /// Verify a Kimchi proof using a built-in Vesta IPA SRS.
    /// `srs_log2_size` selects the supported built-in SRS by polynomial size.
    /// `pubs_bytes` is the flat concatenation of 32-byte compressed `Fp` field elements.
    /// `rng_seed` is a 32-byte seed for the deterministic ChaCha20 RNG.
    fn verify_proof_with_builtin_srs(
        verifier_index_bytes: &[u8],
        srs_log2_size: u8,
        proof_bytes: &[u8],
        pubs_bytes: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<(), VerifyError> {
        imp::verify_proof_with_builtin_srs(
            verifier_index_bytes,
            srs_log2_size,
            proof_bytes,
            pubs_bytes,
            rng_seed,
        )
    }

    /// Validate a Kimchi verification key using a built-in Vesta IPA SRS.
    fn validate_key_with_builtin_srs(
        verifier_index_bytes: &[u8],
        srs_log2_size: u8,
    ) -> Result<(), VerifyError> {
        imp::validate_key_with_builtin_srs(verifier_index_bytes, srs_log2_size)
    }
}

#[cfg(feature = "std")]
mod imp {
    use super::VerifyError;
    use ark_ff::MontFp;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use blake2::{digest::consts::U32, Blake2b, Digest};
    use kimchi::{
        circuits::{
            constraints::FeatureFlags,
            lookup::lookups::{LookupFeatures, LookupInfo, LookupPatterns},
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
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{Arc, OnceLock},
    };

    type NativeOpeningProof = OpeningProof<Vesta, FULL_ROUNDS>;
    type NativeProof = ProverProof<Vesta, NativeOpeningProof, FULL_ROUNDS>;
    type NativeSrs = IpaSrs<Vesta>;
    type NativeVerifierIndex = VerifierIndex<FULL_ROUNDS, Vesta, NativeSrs>;
    type Blake2b256 = Blake2b<U32>;

    // This is the consensus-supported Kimchi shape profile. Keep these bounds
    // aligned with runtime limits and benchmark the maximum accepted shape.
    const MAX_ENCODED_PROOF_BYTES: usize = 262_144;
    const MAX_ENCODED_VERIFIER_INDEX_BYTES: usize = 65_536;
    const MIN_DOMAIN_LOG2_SIZE: u8 = 10;
    const MAX_DOMAIN_LOG2_SIZE: u8 = 16;
    const MAX_PUBLIC_INPUTS: usize = 64;
    const MAX_PREVIOUS_CHALLENGES: usize = 3;
    const MAX_LOOKUPS_PER_ROW: usize = 4;
    const MAX_JOINT_LOOKUP_SIZE: u32 = 3;
    const MAX_SORTED_LOOKUP_COMMITMENTS: usize = MAX_LOOKUPS_PER_ROW + 1;

    // Full canonical digests pin every consensus-supported Vesta16 parameter.
    const VESTA_SRS_16_DIGEST: [u8; 32] = [
        118, 145, 96, 85, 33, 218, 182, 195, 62, 93, 252, 115, 198, 97, 194, 14, 79, 26, 208, 65,
        35, 3, 60, 185, 99, 21, 119, 27, 198, 4, 152, 179,
    ];
    const VESTA_SRS_16_LAGRANGE_DIGESTS: &[(u8, [u8; 32])] = &[
        (
            10,
            [
                62, 107, 180, 44, 172, 35, 75, 215, 130, 61, 38, 219, 105, 153, 182, 109, 87, 79,
                51, 75, 239, 152, 82, 100, 184, 102, 245, 0, 193, 5, 165, 179,
            ],
        ),
        (
            11,
            [
                212, 133, 142, 228, 29, 175, 56, 124, 161, 194, 216, 139, 166, 187, 85, 36, 100,
                242, 6, 208, 89, 2, 218, 229, 116, 234, 162, 168, 83, 192, 204, 218,
            ],
        ),
        (
            12,
            [
                95, 184, 34, 197, 62, 121, 185, 248, 172, 60, 7, 129, 158, 48, 206, 35, 157, 190,
                131, 54, 231, 204, 51, 154, 48, 72, 120, 152, 236, 27, 247, 165,
            ],
        ),
        (
            13,
            [
                195, 180, 144, 87, 222, 177, 101, 16, 98, 56, 222, 246, 167, 78, 234, 237, 161,
                209, 206, 221, 242, 27, 219, 88, 82, 208, 130, 42, 203, 161, 208, 226,
            ],
        ),
        (
            14,
            [
                66, 25, 87, 90, 108, 51, 238, 67, 107, 87, 228, 196, 42, 88, 198, 230, 176, 182,
                44, 249, 71, 115, 50, 1, 121, 248, 208, 53, 102, 148, 59, 215,
            ],
        ),
        (
            15,
            [
                78, 31, 93, 242, 49, 120, 194, 203, 113, 106, 52, 102, 229, 192, 84, 173, 151, 152,
                232, 187, 71, 74, 186, 58, 97, 40, 139, 166, 104, 213, 174, 110,
            ],
        ),
        (
            16,
            [
                24, 109, 49, 100, 59, 18, 111, 130, 33, 215, 232, 222, 105, 21, 21, 53, 69, 167,
                93, 234, 34, 149, 170, 1, 148, 38, 12, 195, 85, 87, 178, 80,
            ],
        ),
    ];

    static VESTA_SRS_16: OnceLock<Arc<NativeSrs>> = OnceLock::new();
    static VESTA_SRS_16_PARAMETER_CHECK: OnceLock<bool> = OnceLock::new();

    pub(super) fn prewarm_builtin_srs(
        srs_log2_size: u8,
        domain_log2_sizes: &[u8],
    ) -> Result<(), VerifyError> {
        if domain_log2_sizes.iter().any(|&domain_log2_size| {
            !(MIN_DOMAIN_LOG2_SIZE..=MAX_DOMAIN_LOG2_SIZE).contains(&domain_log2_size)
                || domain_log2_size > srs_log2_size
        }) {
            return Err(VerifyError::InvalidVerificationKey);
        }

        let srs = builtin_srs(srs_log2_size)?;

        for &domain_log2_size in domain_log2_sizes {
            let domain_size = 1usize
                .checked_shl(u32::from(domain_log2_size))
                .ok_or(VerifyError::InvalidVerificationKey)?;

            let basis = srs.get_lagrange_basis_from_domain_size(domain_size);
            if !lagrange_basis_matches_expected(domain_log2_size, basis.as_slice()) {
                return Err(VerifyError::IncompatibleParameters);
            }
        }

        Ok(())
    }

    pub(super) fn verify_proof_with_builtin_srs(
        verifier_index_bytes: &[u8],
        srs_log2_size: u8,
        proof_bytes: &[u8],
        pubs_bytes: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<(), VerifyError> {
        catch_unwind(AssertUnwindSafe(|| {
            let srs = builtin_srs(srs_log2_size)?;
            verify_proof_with_srs(verifier_index_bytes, srs, proof_bytes, pubs_bytes, rng_seed)
        }))
        .unwrap_or_else(|_| {
            log::warn!("Kimchi verification panicked while processing malformed input");
            Err(VerifyError::InvalidProofData)
        })
    }

    pub(super) fn validate_key_with_builtin_srs(
        verifier_index_bytes: &[u8],
        srs_log2_size: u8,
    ) -> Result<(), VerifyError> {
        catch_unwind(AssertUnwindSafe(|| {
            let mut verifier_index = decode_verifier_index(verifier_index_bytes)?;
            let srs = builtin_srs(srs_log2_size)?;
            prepare_verifier_index(&mut verifier_index, srs)
        }))
        .unwrap_or_else(|_| {
            log::warn!("Kimchi key validation panicked while processing malformed input");
            Err(VerifyError::InvalidVerificationKey)
        })
    }

    fn verify_proof_with_srs(
        verifier_index_bytes: &[u8],
        srs: Arc<NativeSrs>,
        proof_bytes: &[u8],
        pubs_bytes: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<(), VerifyError> {
        let proof = decode_proof(proof_bytes)?;

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
        validate_proof_shape(&proof, &verifier_index, &srs)?;
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

    fn decode_proof(bytes: &[u8]) -> Result<NativeProof, VerifyError> {
        if bytes.len() > MAX_ENCODED_PROOF_BYTES {
            return Err(VerifyError::InvalidProofData);
        }

        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard().with_limit::<MAX_ENCODED_PROOF_BYTES>(),
        )
        .and_then(|(proof, consumed)| {
            (consumed == bytes.len())
                .then_some(proof)
                .ok_or(bincode::error::DecodeError::Other(
                    "trailing Kimchi proof bytes",
                ))
        })
        .inspect_err(|e| log::debug!("Cannot decode Kimchi proof bytes: {e}"))
        .map_err(|_| VerifyError::InvalidProofData)
    }

    fn decode_verifier_index(bytes: &[u8]) -> Result<NativeVerifierIndex, VerifyError> {
        if bytes.len() > MAX_ENCODED_VERIFIER_INDEX_BYTES {
            return Err(VerifyError::InvalidVerificationKey);
        }

        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard().with_limit::<MAX_ENCODED_VERIFIER_INDEX_BYTES>(),
        )
        .and_then(|(verifier_index, consumed)| {
            (consumed == bytes.len()).then_some(verifier_index).ok_or(
                bincode::error::DecodeError::Other("trailing Kimchi verifier index bytes"),
            )
        })
        .inspect_err(|e| log::debug!("Cannot decode Kimchi verifier index: {e}"))
        .map_err(|_| VerifyError::InvalidVerificationKey)
    }

    fn builtin_srs(log2_size: u8) -> Result<Arc<NativeSrs>, VerifyError> {
        match log2_size {
            16 => {
                let srs = Arc::clone(
                    VESTA_SRS_16.get_or_init(|| Arc::new(IpaSrs::<Vesta>::create(1usize << 16))),
                );
                let parameters_match = VESTA_SRS_16_PARAMETER_CHECK
                    .get_or_init(|| vesta_srs_16_matches_expected(&srs));
                if !*parameters_match {
                    return Err(VerifyError::IncompatibleParameters);
                }
                Ok(srs)
            }
            _ => Err(VerifyError::InvalidVerificationKey),
        }
    }

    fn vesta_srs_16_matches_expected(srs: &NativeSrs) -> bool {
        srs.g.len() == 1usize << 16
            && srs_digest(srs).is_ok_and(|digest| digest == VESTA_SRS_16_DIGEST)
    }

    fn lagrange_basis_matches_expected(
        domain_log2_size: u8,
        basis: &[poly_commitment::PolyComm<Vesta>],
    ) -> bool {
        VESTA_SRS_16_LAGRANGE_DIGESTS
            .iter()
            .find_map(|(log2_size, digest)| (*log2_size == domain_log2_size).then_some(digest))
            .is_some_and(|expected| {
                basis.len() == 1usize << domain_log2_size
                    && lagrange_basis_digest(domain_log2_size, basis)
                        .is_ok_and(|digest| &digest == expected)
            })
    }

    fn srs_digest(srs: &NativeSrs) -> Result<[u8; 32], VerifyError> {
        let mut hasher = Blake2b256::new();
        hasher.update(b"kimchi:v1:vesta16:srs");
        hash_usize(&mut hasher, srs.g.len());
        for point in &srs.g {
            hash_point(&mut hasher, point)?;
        }
        hash_point(&mut hasher, &srs.h)?;
        Ok(hasher.finalize().into())
    }

    fn lagrange_basis_digest(
        domain_log2_size: u8,
        basis: &[poly_commitment::PolyComm<Vesta>],
    ) -> Result<[u8; 32], VerifyError> {
        let mut hasher = Blake2b256::new();
        hasher.update(b"kimchi:v1:vesta16:lagrange");
        hasher.update([domain_log2_size]);
        hash_usize(&mut hasher, basis.len());
        for commitment in basis {
            hash_usize(&mut hasher, commitment.chunks.len());
            for point in &commitment.chunks {
                hash_point(&mut hasher, point)?;
            }
        }
        Ok(hasher.finalize().into())
    }

    fn hash_usize(hasher: &mut Blake2b256, value: usize) {
        hasher.update((value as u64).to_le_bytes());
    }

    fn hash_point(hasher: &mut Blake2b256, point: &Vesta) -> Result<(), VerifyError> {
        let mut compressed = [0_u8; 33];
        point
            .serialize_compressed(compressed.as_mut_slice())
            .map_err(|_| VerifyError::IncompatibleParameters)?;
        hasher.update(compressed);
        Ok(())
    }

    fn prepare_verifier_index(
        verifier_index: &mut NativeVerifierIndex,
        srs: Arc<NativeSrs>,
    ) -> Result<(), VerifyError> {
        validate_verifier_index_shape(verifier_index, &srs)?;

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

    fn validate_verifier_index_shape(
        verifier_index: &NativeVerifierIndex,
        srs: &NativeSrs,
    ) -> Result<(), VerifyError> {
        let domain_size = usize::try_from(verifier_index.domain.size)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let domain_log2_size = verifier_index.domain.log_size_of_group;
        let max_poly_size = verifier_index.max_poly_size;
        let srs_size = srs.max_poly_size();

        if domain_size == 0
            || !domain_size.is_power_of_two()
            || domain_log2_size != domain_size.ilog2()
            || !(u32::from(MIN_DOMAIN_LOG2_SIZE)..=u32::from(MAX_DOMAIN_LOG2_SIZE))
                .contains(&domain_log2_size)
            || max_poly_size != domain_size
            || !max_poly_size.is_power_of_two()
            || max_poly_size > srs_size
            || verifier_index.zk_rows >= verifier_index.domain.size
            || verifier_index.public > domain_size
            || verifier_index.public > MAX_PUBLIC_INPUTS
            || verifier_index.prev_challenges > MAX_PREVIOUS_CHALLENGES
        {
            return Err(VerifyError::InvalidVerificationKey);
        }

        let expected_lookup_patterns = structural_lookup_patterns(verifier_index);
        let expected_lookup_features = LookupFeatures {
            patterns: expected_lookup_patterns,
            joint_lookup_used: expected_lookup_patterns.joint_lookups_used(),
            uses_runtime_tables: false,
        };
        let expected_lookup_info = LookupInfo::create(expected_lookup_features);

        if verifier_index.lookup_index.is_some()
            != (expected_lookup_patterns != LookupPatterns::default())
        {
            return Err(VerifyError::InvalidVerificationKey);
        }

        if let Some(lookup_index) = &verifier_index.lookup_index {
            if lookup_index.lookup_info.max_per_row > MAX_LOOKUPS_PER_ROW
                || lookup_index.lookup_info.max_joint_size > MAX_JOINT_LOOKUP_SIZE
                || lookup_index.lookup_info.max_per_row != expected_lookup_info.max_per_row
                || lookup_index.lookup_info.max_joint_size != expected_lookup_info.max_joint_size
                || lookup_index.lookup_info.features != expected_lookup_features
                || lookup_index.joint_lookup_used != expected_lookup_features.joint_lookup_used
                || lookup_index.lookup_selectors.xor.is_some() != expected_lookup_patterns.xor
                || lookup_index.lookup_selectors.lookup.is_some() != expected_lookup_patterns.lookup
                || lookup_index.lookup_selectors.range_check.is_some()
                    != expected_lookup_patterns.range_check
                || lookup_index.lookup_selectors.ffmul.is_some()
                    != expected_lookup_patterns.foreign_field_mul
                || lookup_index.runtime_tables_selector.is_some()
                || lookup_index.lookup_table.len() < expected_lookup_info.max_joint_size as usize
                || lookup_index.lookup_table.len() > MAX_JOINT_LOOKUP_SIZE as usize
                || lookup_index
                    .lookup_table
                    .iter()
                    .any(|commitment| !has_one_chunk(commitment))
                || !optional_commitment_has_one_chunk(lookup_index.lookup_selectors.xor.as_ref())
                || !optional_commitment_has_one_chunk(lookup_index.lookup_selectors.lookup.as_ref())
                || !optional_commitment_has_one_chunk(
                    lookup_index.lookup_selectors.range_check.as_ref(),
                )
                || !optional_commitment_has_one_chunk(lookup_index.lookup_selectors.ffmul.as_ref())
                || !optional_commitment_has_one_chunk(lookup_index.table_ids.as_ref())
            {
                return Err(VerifyError::InvalidVerificationKey);
            }
        }

        if verifier_index
            .sigma_comm
            .iter()
            .chain(verifier_index.coefficients_comm.iter())
            .any(|commitment| !has_one_chunk(commitment))
            || [
                &verifier_index.generic_comm,
                &verifier_index.psm_comm,
                &verifier_index.complete_add_comm,
                &verifier_index.mul_comm,
                &verifier_index.emul_comm,
                &verifier_index.endomul_scalar_comm,
            ]
            .into_iter()
            .any(|commitment| !has_one_chunk(commitment))
            || [
                verifier_index.range_check0_comm.as_ref(),
                verifier_index.range_check1_comm.as_ref(),
                verifier_index.foreign_field_add_comm.as_ref(),
                verifier_index.foreign_field_mul_comm.as_ref(),
                verifier_index.xor_comm.as_ref(),
                verifier_index.rot_comm.as_ref(),
            ]
            .into_iter()
            .any(|commitment| !optional_commitment_has_one_chunk(commitment))
        {
            return Err(VerifyError::InvalidVerificationKey);
        }

        Ok(())
    }

    fn validate_proof_shape(
        proof: &NativeProof,
        verifier_index: &NativeVerifierIndex,
        srs: &NativeSrs,
    ) -> Result<(), VerifyError> {
        validate_verifier_index_shape(verifier_index, srs)?;

        let expected_rounds = verifier_index.max_poly_size.ilog2() as usize;
        if proof.proof.lr.len() != expected_rounds
            || proof.prev_challenges.len() != verifier_index.prev_challenges
            || proof.prev_challenges.len() > MAX_PREVIOUS_CHALLENGES
            || proof.prev_challenges.iter().any(|challenge| {
                challenge.chals.len() != expected_rounds || !has_one_chunk(&challenge.comm)
            })
            || proof
                .commitments
                .w_comm
                .iter()
                .any(|commitment| !has_one_chunk(commitment))
            || !has_one_chunk(&proof.commitments.z_comm)
            || proof.commitments.t_comm.chunks.is_empty()
            || proof.commitments.t_comm.chunks.len() > 7
            || proof.commitments.lookup.as_ref().is_some_and(|lookup| {
                lookup.sorted.len() > MAX_SORTED_LOOKUP_COMMITMENTS
                    || lookup
                        .sorted
                        .iter()
                        .any(|commitment| !has_one_chunk(commitment))
                    || !has_one_chunk(&lookup.aggreg)
                    || lookup.runtime.is_some()
            })
            || proof.evals.runtime_lookup_table.is_some()
            || proof.evals.runtime_lookup_table_selector.is_some()
        {
            return Err(VerifyError::InvalidProofData);
        }

        Ok(())
    }

    fn has_one_chunk(commitment: &poly_commitment::PolyComm<Vesta>) -> bool {
        commitment.chunks.len() == 1
    }

    fn optional_commitment_has_one_chunk(
        commitment: Option<&poly_commitment::PolyComm<Vesta>>,
    ) -> bool {
        commitment.is_none_or(has_one_chunk)
    }

    fn structural_lookup_patterns(verifier_index: &NativeVerifierIndex) -> LookupPatterns {
        LookupPatterns {
            xor: verifier_index.xor_comm.is_some(),
            lookup: verifier_index
                .lookup_index
                .as_ref()
                .is_some_and(|lookup_index| lookup_index.lookup_selectors.lookup.is_some()),
            range_check: verifier_index.range_check0_comm.is_some()
                || verifier_index.range_check1_comm.is_some()
                || verifier_index.rot_comm.is_some(),
            foreign_field_mul: verifier_index.foreign_field_mul_comm.is_some(),
        }
    }

    fn compute_feature_flags(verifier_index: &NativeVerifierIndex) -> FeatureFlags {
        let xor = verifier_index.xor_comm.is_some();
        let range_check0 = verifier_index.range_check0_comm.is_some();
        let range_check1 = verifier_index.range_check1_comm.is_some();
        let foreign_field_add = verifier_index.foreign_field_add_comm.is_some();
        let foreign_field_mul = verifier_index.foreign_field_mul_comm.is_some();
        let rot = verifier_index.rot_comm.is_some();

        let patterns = structural_lookup_patterns(verifier_index);

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
                uses_runtime_tables: false,
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

    #[cfg(test)]
    mod tests {
        use super::*;

        const PROOF: &[u8] =
            include_bytes!("../../verifiers/kimchi/src/resources/generated_4096/proof.bin");
        const VERIFIER_INDEX: &[u8] = include_bytes!(
            "../../verifiers/kimchi/src/resources/generated_4096/verifier_index.bin"
        );
        const MIN_DOMAIN_VERIFIER_INDEX: &[u8] = include_bytes!(
            "../../verifiers/kimchi/src/resources/generated_1024/verifier_index.bin"
        );
        const MIN_DOMAIN_PROOF: &[u8] =
            include_bytes!("../../verifiers/kimchi/src/resources/generated_1024/proof.bin");
        const MIN_DOMAIN_PUBS: &[u8] =
            include_bytes!("../../verifiers/kimchi/src/resources/generated_1024/pubs.bin");
        const MAX_DOMAIN_VERIFIER_INDEX: &[u8] = include_bytes!(
            "../../verifiers/kimchi/src/resources/generated_65536_xor_lookup_recursive_3_pubs_64/verifier_index.bin"
        );
        const MAX_DOMAIN_PROOF: &[u8] = include_bytes!(
            "../../verifiers/kimchi/src/resources/generated_65536_xor_lookup_recursive_3_pubs_64/proof.bin"
        );
        const MAX_DOMAIN_PUBS: &[u8] = include_bytes!(
            "../../verifiers/kimchi/src/resources/generated_65536_xor_lookup_recursive_3_pubs_64/pubs.bin"
        );

        #[test]
        fn decoders_reject_trailing_bytes() {
            let mut proof = PROOF.to_vec();
            proof.push(0);
            assert_eq!(decode_proof(&proof), Err(VerifyError::InvalidProofData));

            let mut verifier_index = VERIFIER_INDEX.to_vec();
            verifier_index.push(0);
            assert!(matches!(
                decode_verifier_index(&verifier_index),
                Err(VerifyError::InvalidVerificationKey)
            ));
        }

        #[test]
        fn proof_shape_rejects_more_ipa_rounds_than_the_verifier_index() {
            let mut proof = decode_proof(PROOF).expect("fixture proof should decode");
            let verifier_index = decode_verifier_index(VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            proof.proof.lr.push(proof.proof.lr[0]);

            assert_eq!(
                validate_proof_shape(&proof, &verifier_index, &builtin_srs(16).unwrap()),
                Err(VerifyError::InvalidProofData)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_unbounded_previous_challenges() {
            let mut verifier_index = decode_verifier_index(VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            verifier_index.prev_challenges = MAX_PREVIOUS_CHALLENGES + 1;

            assert_eq!(
                validate_verifier_index_shape(&verifier_index, &builtin_srs(16).unwrap()),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_accepts_domain_boundaries() {
            let srs = builtin_srs(16).expect("built-in SRS should be available");

            for verifier_index_bytes in [MIN_DOMAIN_VERIFIER_INDEX, MAX_DOMAIN_VERIFIER_INDEX] {
                let verifier_index = decode_verifier_index(verifier_index_bytes)
                    .expect("fixture verifier index should decode");
                assert_eq!(validate_verifier_index_shape(&verifier_index, &srs), Ok(()));
            }
        }

        #[test]
        fn valid_v1_boundary_proofs_verify() {
            for (verifier_index, proof, pubs) in [
                (MIN_DOMAIN_VERIFIER_INDEX, MIN_DOMAIN_PROOF, MIN_DOMAIN_PUBS),
                (MAX_DOMAIN_VERIFIER_INDEX, MAX_DOMAIN_PROOF, MAX_DOMAIN_PUBS),
            ] {
                assert_eq!(
                    verify_proof_with_builtin_srs(verifier_index, 16, proof, pubs, &[0; 32]),
                    Ok(())
                );
            }
        }

        #[test]
        fn verifier_index_shape_rejects_domain_below_v1_minimum() {
            let mut verifier_index = decode_verifier_index(VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            verifier_index.domain.size = 1 << (MIN_DOMAIN_LOG2_SIZE - 1);
            verifier_index.domain.log_size_of_group = u32::from(MIN_DOMAIN_LOG2_SIZE - 1);
            verifier_index.max_poly_size = 1 << (MIN_DOMAIN_LOG2_SIZE - 1);

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_more_than_maximum_public_inputs() {
            let mut verifier_index = decode_verifier_index(VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            verifier_index.public = MAX_PUBLIC_INPUTS + 1;

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_chunked_profile() {
            let mut verifier_index = decode_verifier_index(VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            verifier_index.max_poly_size *= 2;

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_incoherent_lookup_metadata() {
            let mut verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            verifier_index
                .lookup_index
                .as_mut()
                .expect("maximum fixture should use lookups")
                .lookup_info
                .max_per_row -= 1;

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_lookup_index_without_a_lookup_pattern() {
            let mut verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            verifier_index.xor_comm = None;
            let lookup_index = verifier_index
                .lookup_index
                .as_mut()
                .expect("maximum fixture should use lookups");
            lookup_index.lookup_selectors.xor = None;
            lookup_index.lookup_info = LookupInfo::create(LookupFeatures::default());
            lookup_index.joint_lookup_used = false;

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_too_few_lookup_table_columns() {
            let mut verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            verifier_index
                .lookup_index
                .as_mut()
                .expect("maximum fixture should use lookups")
                .lookup_table
                .pop();

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_incoherent_joint_lookup_flag() {
            let mut verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            let lookup_index = verifier_index
                .lookup_index
                .as_mut()
                .expect("maximum fixture should use lookups");
            lookup_index.joint_lookup_used = !lookup_index.joint_lookup_used;

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_runtime_tables() {
            let mut verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            let lookup_index = verifier_index
                .lookup_index
                .as_mut()
                .expect("maximum fixture should use lookups");
            lookup_index.lookup_info.features.uses_runtime_tables = true;

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn verifier_index_shape_rejects_runtime_table_selector() {
            let mut verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");
            let lookup_index = verifier_index
                .lookup_index
                .as_mut()
                .expect("maximum fixture should use lookups");
            lookup_index.runtime_tables_selector = Some(
                lookup_index
                    .lookup_table
                    .first()
                    .expect("maximum fixture should include a lookup table")
                    .clone(),
            );

            assert_eq!(
                validate_verifier_index_shape(
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidVerificationKey)
            );
        }

        #[test]
        fn proof_shape_rejects_runtime_table_commitment() {
            let mut proof = decode_proof(MAX_DOMAIN_PROOF).expect("fixture proof should decode");
            let lookup = proof
                .commitments
                .lookup
                .as_mut()
                .expect("maximum fixture should use lookups");
            lookup.runtime = Some(lookup.aggreg.clone());
            let verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");

            assert_eq!(
                validate_proof_shape(
                    &proof,
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidProofData)
            );
        }

        #[test]
        fn proof_shape_rejects_runtime_table_evaluations() {
            let mut proof = decode_proof(MAX_DOMAIN_PROOF).expect("fixture proof should decode");
            proof.evals.runtime_lookup_table = Some(proof.evals.w[0].clone());
            let verifier_index = decode_verifier_index(MAX_DOMAIN_VERIFIER_INDEX)
                .expect("fixture verifier index should decode");

            assert_eq!(
                validate_proof_shape(
                    &proof,
                    &verifier_index,
                    &builtin_srs(16).expect("built-in SRS should be available"),
                ),
                Err(VerifyError::InvalidProofData)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prewarm_rejects_unsupported_srs() {
        assert_eq!(
            prewarm_kimchi_builtin_srs(15, &[]),
            Err(VerifyError::InvalidVerificationKey)
        );
    }

    #[test]
    fn prewarm_rejects_domain_larger_than_srs_before_initialization() {
        assert_eq!(
            prewarm_kimchi_builtin_srs(16, &[17]),
            Err(VerifyError::InvalidVerificationKey)
        );
    }

    #[test]
    fn prewarm_rejects_domain_below_v1_minimum() {
        assert_eq!(
            prewarm_kimchi_builtin_srs(16, &[9]),
            Err(VerifyError::InvalidVerificationKey)
        );
    }
}
