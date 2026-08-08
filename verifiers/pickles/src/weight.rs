// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Conservative weights for `pallet_pickles_verifier`.
//!
//! PicklesV1 has one fixed Pallas15 outer verifier and one fixed Vesta16
//! accumulator check. The pallet therefore charges a single upper bound rather
//! than returning a proof-dependent post-dispatch weight.

use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Weight functions needed for `pallet_pickles_verifier`.
pub trait WeightInfo {
    fn verify_proof() -> Weight;
    fn get_vk() -> Weight;
    fn validate_vk() -> Weight;
    fn compute_statement_hash() -> Weight;
    fn register_vk() -> Weight;
    fn unregister_vk() -> Weight;
}

impl WeightInfo for () {
    fn verify_proof() -> Weight {
        // Deliberately generous until reference-hardware weights are regenerated.
        Weight::from_parts(500_000_000_000, 0)
    }

    fn get_vk() -> Weight {
        Weight::from_parts(5_000_000, 7_120).saturating_add(RocksDbWeight::get().reads(1_u64))
    }

    fn validate_vk() -> Weight {
        Weight::from_parts(100_000_000_000, 0)
    }

    fn compute_statement_hash() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }

    fn register_vk() -> Weight {
        Weight::from_parts(100_100_000_000, 7_120)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }

    fn unregister_vk() -> Weight {
        Weight::from_parts(35_000_000, 7_120)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
}
