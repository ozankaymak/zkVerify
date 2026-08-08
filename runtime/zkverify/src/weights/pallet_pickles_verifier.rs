// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Conservative deployment weights for `pallet_pickles_verifier`.
//!
//! These bounds intentionally include margin. Regenerate this file with the
//! pallet benchmark after measuring the final reference-hardware build.

#![allow(missing_docs)]

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

pub struct ZKVWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> pallet_pickles_verifier::WeightInfo for ZKVWeight<T> {
    fn verify_proof() -> Weight {
        Weight::from_parts(500_000_000_000, 0)
    }

    fn get_vk() -> Weight {
        Weight::from_parts(5_000_000, 7_120).saturating_add(T::DbWeight::get().reads(1_u64))
    }

    fn validate_vk() -> Weight {
        Weight::from_parts(100_000_000_000, 0)
    }

    fn compute_statement_hash() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }

    fn register_vk() -> Weight {
        Weight::from_parts(100_100_000_000, 7_120)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }

    fn unregister_vk() -> Weight {
        Weight::from_parts(35_000_000, 7_120)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
}
