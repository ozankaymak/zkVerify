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

use frame_support::weights::Weight;

const CUSTOM_GATE_WEIGHT_MARGIN_PERCENT: u64 = 25;

/// Weight functions needed for `pallet_kimchi_verifier_verify_proof`.
pub trait WeightInfo {
    fn verify_proof_domain_1024() -> Weight {
        Self::verify_proof_domain_4096()
    }

    fn verify_proof_domain_2048() -> Weight {
        Self::verify_proof_domain_4096()
    }

    fn verify_proof_domain_4096() -> Weight;

    fn verify_proof_domain_4096_pubs_64() -> Weight {
        Self::verify_proof_domain_4096()
    }

    fn verify_proof_domain_65536_pubs_64() -> Weight {
        Self::verify_proof_domain_4096()
    }

    fn verify_proof_domain_65536_recursive_3_pubs_64() -> Weight {
        Self::verify_proof_domain_65536_pubs_64()
    }

    fn verify_proof_domain_65536_lookup_recursive_3_pubs_64() -> Weight {
        Self::verify_proof_domain_65536_recursive_3_pubs_64()
    }

    fn verify_proof_domain_65536_xor_lookup_recursive_3_pubs_64() -> Weight {
        Self::verify_proof_domain_65536_lookup_recursive_3_pubs_64()
    }

    fn verify_proof_max_supported() -> Weight {
        let weights = [
            Self::verify_proof_domain_1024(),
            Self::verify_proof_domain_2048(),
            Self::verify_proof_domain_4096(),
            Self::verify_proof_domain_4096_pubs_64(),
            Self::verify_proof_domain_65536_pubs_64(),
            Self::verify_proof_domain_65536_recursive_3_pubs_64(),
            Self::verify_proof_domain_65536_lookup_recursive_3_pubs_64(),
            Self::verify_proof_domain_65536_xor_lookup_recursive_3_pubs_64(),
        ];
        let measured_max = weights
            .into_iter()
            .fold(Weight::from_parts(0, 0), |max, weight| {
                Weight::from_parts(
                    max.ref_time().max(weight.ref_time()),
                    max.proof_size().max(weight.proof_size()),
                )
            });

        // XOR benchmarks the heaviest lookup shape. Keep additional headroom
        // for accepted combinations of the remaining optional custom gates.
        Weight::from_parts(
            measured_max
                .ref_time()
                .saturating_mul(100 + CUSTOM_GATE_WEIGHT_MARGIN_PERCENT)
                .saturating_div(100),
            measured_max.proof_size(),
        )
    }
}

// For backwards compatibility and tests.
impl WeightInfo for () {
    fn verify_proof_domain_4096() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `0`
        //  Estimated: `0`
        // Minimum execution time: 287_781_000_000 picoseconds.
        Weight::from_parts(290_415_000_000, 0)
    }
}
