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

//! Kimchi IPA opening verification with only the final Vesta MSM accelerated natively.

use alloc::{vec, vec::Vec};

use ark_ec::AffineRepr;
use ark_ff::{One, UniformRand, Zero};
#[cfg(feature = "std")]
use ark_poly::EvaluationDomain;
use kimchi::groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta};
use mina_poseidon::{pasta::FULL_ROUNDS, sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{
        b_poly, b_poly_coefficients, combine_commitments, shift_scalar, BatchEvaluationProof,
        CommitmentCurve, PolyComm,
    },
    ipa::{endos, OpeningProof},
    OpenProof, SRS as _,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::builtin_srs::BuiltinSrs;

type UpstreamOpeningProof = OpeningProof<Vesta, FULL_ROUNDS>;

/// Wire-compatible Kimchi opening proof that delegates only the final MSM to the host.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcceleratedOpeningProof(UpstreamOpeningProof);

impl OpenProof<Vesta, FULL_ROUNDS> for AcceleratedOpeningProof {
    type SRS = BuiltinSrs;

    #[cfg(feature = "std")]
    fn open<EFqSponge, RNG, D: EvaluationDomain<Fp>>(
        srs: &Self::SRS,
        group_map: &<Vesta as CommitmentCurve>::Map,
        plnms: &[(
            poly_commitment::utils::DensePolynomialOrEvaluations<'_, Fp, D>,
            PolyComm<Fp>,
        )],
        elm: &[Fp],
        polyscale: Fp,
        evalscale: Fp,
        sponge: EFqSponge,
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge: Clone + FqSponge<<Vesta as AffineRepr>::BaseField, Vesta, Fp, FULL_ROUNDS>,
        RNG: RngCore + CryptoRng,
    {
        let _ = (
            srs, group_map, plnms, elm, polyscale, evalscale, sponge, rng,
        );
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        group_map: &<Vesta as CommitmentCurve>::Map,
        batch: &mut [BatchEvaluationProof<Vesta, EFqSponge, Self, FULL_ROUNDS>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<<Vesta as AffineRepr>::BaseField, Vesta, Fp, FULL_ROUNDS>,
        RNG: RngCore + CryptoRng,
    {
        verify_with_native_msm(srs, group_map, batch, rng)
    }
}

/// Benchmark-only opening proof that preserves transcript construction while
/// omitting the final IPA opening verification.
#[cfg(feature = "runtime-benchmarks")]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct NoopOpeningProof(UpstreamOpeningProof);

#[cfg(feature = "runtime-benchmarks")]
impl OpenProof<Vesta, FULL_ROUNDS> for NoopOpeningProof {
    type SRS = BuiltinSrs;

    #[cfg(feature = "std")]
    fn open<EFqSponge, RNG, D: EvaluationDomain<Fp>>(
        srs: &Self::SRS,
        group_map: &<Vesta as CommitmentCurve>::Map,
        plnms: &[(
            poly_commitment::utils::DensePolynomialOrEvaluations<'_, Fp, D>,
            PolyComm<Fp>,
        )],
        elm: &[Fp],
        polyscale: Fp,
        evalscale: Fp,
        sponge: EFqSponge,
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge: Clone + FqSponge<<Vesta as AffineRepr>::BaseField, Vesta, Fp, FULL_ROUNDS>,
        RNG: RngCore + CryptoRng,
    {
        let _ = (
            srs, group_map, plnms, elm, polyscale, evalscale, sponge, rng,
        );
        unreachable!("built-in Kimchi SRS is verifier-only")
    }

    fn verify<EFqSponge, RNG>(
        _srs: &Self::SRS,
        _group_map: &<Vesta as CommitmentCurve>::Map,
        _batch: &mut [BatchEvaluationProof<Vesta, EFqSponge, Self, FULL_ROUNDS>],
        _rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<<Vesta as AffineRepr>::BaseField, Vesta, Fp, FULL_ROUNDS>,
        RNG: RngCore + CryptoRng,
    {
        true
    }
}

/// Builds the complete IPA verification equation in WASM and delegates only
/// its final variable-base MSM to the native host.
fn verify_with_native_msm<EFqSponge, RNG>(
    srs: &BuiltinSrs,
    group_map: &<Vesta as CommitmentCurve>::Map,
    batch: &mut [BatchEvaluationProof<Vesta, EFqSponge, AcceleratedOpeningProof, FULL_ROUNDS>],
    rng: &mut RNG,
) -> bool
where
    EFqSponge: FqSponge<<Vesta as AffineRepr>::BaseField, Vesta, Fp, FULL_ROUNDS>,
    RNG: RngCore + CryptoRng,
{
    let nonzero_length = srs.max_poly_size();
    let padded_length = nonzero_length.next_power_of_two();
    if nonzero_length == 0 || nonzero_length != padded_length {
        return false;
    }
    let (_, endo_r) = endos::<Vesta>();

    let mut h_scalar = Fp::zero();
    let mut g_scalars = vec![Fp::zero(); padded_length];
    let mut points = Vec::new();
    let mut scalars = Vec::new();

    let rand_base = Fp::rand(rng);
    let sg_rand_base = Fp::rand(rng);
    let mut rand_base_i = Fp::one();
    let mut sg_rand_base_i = Fp::one();

    for BatchEvaluationProof {
        sponge,
        evaluation_points,
        polyscale,
        evalscale,
        evaluations,
        opening,
        combined_inner_product,
    } in batch.iter_mut()
    {
        sponge.absorb_fr(&[shift_scalar::<Vesta>(*combined_inner_product)]);

        let u_base = {
            let t = sponge.challenge_fq();
            let (x, y) = group_map.to_group(t);
            Vesta::of_coordinates(x, y)
        };

        let opening = &opening.0;
        let challenges = opening.challenges::<EFqSponge>(&endo_r, sponge);

        sponge.absorb_g(&[opening.delta]);
        let c = ScalarChallenge::new(sponge.challenge()).to_field(&endo_r);

        let b0 = {
            let mut scale = Fp::one();
            let mut result = Fp::zero();
            for evaluation_point in evaluation_points.iter() {
                result += scale * b_poly(&challenges.chal, *evaluation_point);
                scale *= *evalscale;
            }
            result
        };

        let s = b_poly_coefficients(&challenges.chal);
        let neg_rand_base_i = -rand_base_i;

        points.push(opening.sg);
        scalars.push(neg_rand_base_i * opening.z1 - sg_rand_base_i);

        for (index, term) in s.iter().map(|s| sg_rand_base_i * s).enumerate() {
            let Some(scalar) = g_scalars.get_mut(index) else {
                return false;
            };
            *scalar += term;
        }

        h_scalar -= rand_base_i * opening.z2;

        scalars.push(neg_rand_base_i * (opening.z1 * b0));
        points.push(u_base);

        let rand_base_i_c_i = c * rand_base_i;
        for ((left, right), (challenge_inverse, challenge)) in opening
            .lr
            .iter()
            .zip(challenges.chal_inv.iter().zip(challenges.chal.iter()))
        {
            points.push(*left);
            scalars.push(rand_base_i_c_i * challenge_inverse);

            points.push(*right);
            scalars.push(rand_base_i_c_i * challenge);
        }

        combine_commitments(
            evaluations,
            &mut scalars,
            &mut points,
            *polyscale,
            rand_base_i_c_i,
        );

        scalars.push(rand_base_i_c_i * *combined_inner_product);
        points.push(u_base);

        scalars.push(rand_base_i);
        points.push(opening.delta);

        rand_base_i *= rand_base;
        sg_rand_base_i *= sg_rand_base;
    }

    native::vesta::vesta16_srs_msm(
        nonzero_length as u32,
        h_scalar,
        &g_scalars,
        &points,
        &scalars,
    )
    .is_ok_and(|result| result.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimchi::{proof::ProverProof, verifier::verify_with_rng};
    use mina_curves::pasta::VestaParameters;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
    type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;

    #[test]
    fn accelerated_opening_proof_preserves_fixture_encoding() {
        let proof_bytes = include_bytes!("resources/generated_4096/proof.bin");
        let config = bincode::config::standard();

        let (upstream, upstream_len): (ProverProof<Vesta, UpstreamOpeningProof, FULL_ROUNDS>, _) =
            bincode::serde::decode_from_slice(proof_bytes, config).expect("valid fixture");
        let (accelerated, accelerated_len): (
            ProverProof<Vesta, AcceleratedOpeningProof, FULL_ROUNDS>,
            _,
        ) = bincode::serde::decode_from_slice(proof_bytes, config).expect("valid fixture");

        assert_eq!(upstream_len, proof_bytes.len());
        assert_eq!(accelerated_len, proof_bytes.len());
        assert_eq!(
            bincode::serde::encode_to_vec(upstream, config).expect("encodes"),
            bincode::serde::encode_to_vec(accelerated, config).expect("encodes")
        );
    }

    #[test]
    fn accelerated_verification_accepts_fixture() {
        let config = bincode::config::standard();
        let proof_bytes = include_bytes!("resources/generated_4096/proof.bin");
        let verifier_index_bytes = include_bytes!("resources/generated_4096/verifier_index.bin");

        let (accelerated_proof, _): (ProverProof<Vesta, AcceleratedOpeningProof, FULL_ROUNDS>, _) =
            bincode::serde::decode_from_slice(proof_bytes, config).expect("valid fixture");
        let (mut verifier_index, _): (crate::NativeVerifierIndex, _) =
            bincode::serde::decode_from_slice(verifier_index_bytes, config).expect("valid index");
        crate::prepare_verifier_index(&mut verifier_index, crate::KimchiSrsId::Vesta16)
            .expect("index preparation succeeds");

        let group_map = crate::vesta_group_map();
        let mut accelerated_rng = ChaCha20Rng::from_seed([7_u8; 32]);

        let accelerated_result = verify_with_rng::<
            FULL_ROUNDS,
            Vesta,
            BaseSponge,
            ScalarSponge,
            AcceleratedOpeningProof,
            _,
        >(
            &group_map,
            &verifier_index,
            &accelerated_proof,
            &[],
            &mut accelerated_rng,
        );

        assert!(accelerated_result.is_ok());
    }
}
