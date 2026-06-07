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

#![cfg(feature = "runtime-benchmarks")]

use crate::{Config as VerifierConfig, Kimchi as Verifier, KimchiSrsId, Proof, Pubs, Vk, PUB_SIZE};
use frame_benchmarking::v2::*;
use pallet_verifiers::benchmarking_utils;
use pallet_verifiers::traits::Verifier as _;

pub trait Config: crate::Config {}
pub struct Pallet<T: Config>(crate::Pallet<T>);
impl<T: crate::Config> Config for T {}
pub type Call<T> = pallet_verifiers::Call<T, Verifier<T>>;

const DOMAIN_1024_PROOF: &[u8] = include_bytes!("resources/generated_1024/proof.bin");
const DOMAIN_1024_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_1024/verifier_index.bin");
const DOMAIN_1024_PUBS: &[u8] = include_bytes!("resources/generated_1024/pubs.bin");

const DOMAIN_2048_PROOF: &[u8] = include_bytes!("resources/generated_2048/proof.bin");
const DOMAIN_2048_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_2048/verifier_index.bin");
const DOMAIN_2048_PUBS: &[u8] = include_bytes!("resources/generated_2048/pubs.bin");

const DOMAIN_4096_PROOF: &[u8] = include_bytes!("resources/generated_4096/proof.bin");
const DOMAIN_4096_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_4096/verifier_index.bin");
const DOMAIN_4096_PUBS: &[u8] = &[];

const DOMAIN_4096_PUBS_64_PROOF: &[u8] =
    include_bytes!("resources/generated_4096_pubs_64/proof.bin");
const DOMAIN_4096_PUBS_64_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_4096_pubs_64/verifier_index.bin");
const DOMAIN_4096_PUBS_64_PUBS: &[u8] = include_bytes!("resources/generated_4096_pubs_64/pubs.bin");

const DOMAIN_65536_PUBS_64_PROOF: &[u8] =
    include_bytes!("resources/generated_65536_pubs_64/proof.bin");
const DOMAIN_65536_PUBS_64_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_65536_pubs_64/verifier_index.bin");
const DOMAIN_65536_PUBS_64_PUBS: &[u8] =
    include_bytes!("resources/generated_65536_pubs_64/pubs.bin");

const DOMAIN_65536_RECURSIVE_3_PUBS_64_PROOF: &[u8] =
    include_bytes!("resources/generated_65536_recursive_3_pubs_64/proof.bin");
const DOMAIN_65536_RECURSIVE_3_PUBS_64_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_65536_recursive_3_pubs_64/verifier_index.bin");
const DOMAIN_65536_RECURSIVE_3_PUBS_64_PUBS: &[u8] =
    include_bytes!("resources/generated_65536_recursive_3_pubs_64/pubs.bin");

const DOMAIN_65536_LOOKUP_RECURSIVE_3_PUBS_64_PROOF: &[u8] =
    include_bytes!("resources/generated_65536_lookup_recursive_3_pubs_64/proof.bin");
const DOMAIN_65536_LOOKUP_RECURSIVE_3_PUBS_64_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_65536_lookup_recursive_3_pubs_64/verifier_index.bin");
const DOMAIN_65536_LOOKUP_RECURSIVE_3_PUBS_64_PUBS: &[u8] =
    include_bytes!("resources/generated_65536_lookup_recursive_3_pubs_64/pubs.bin");

const DOMAIN_65536_XOR_LOOKUP_RECURSIVE_3_PUBS_64_PROOF: &[u8] =
    include_bytes!("resources/generated_65536_xor_lookup_recursive_3_pubs_64/proof.bin");
const DOMAIN_65536_XOR_LOOKUP_RECURSIVE_3_PUBS_64_VERIFIER_INDEX: &[u8] =
    include_bytes!("resources/generated_65536_xor_lookup_recursive_3_pubs_64/verifier_index.bin");
const DOMAIN_65536_XOR_LOOKUP_RECURSIVE_3_PUBS_64_PUBS: &[u8] =
    include_bytes!("resources/generated_65536_xor_lookup_recursive_3_pubs_64/pubs.bin");

fn benchmark_data<T: VerifierConfig>(
    proof: &[u8],
    verifier_index: &[u8],
    pubs: &[u8],
) -> (Proof, Vk<T>, Pubs) {
    (
        proof.to_vec(),
        Vk::new(verifier_index.to_vec(), KimchiSrsId::Vesta16),
        decode_pubs(pubs),
    )
}

fn decode_pubs(bytes: &[u8]) -> Pubs {
    assert!(
        bytes.len().is_multiple_of(PUB_SIZE),
        "Kimchi public input fixture must be a sequence of {PUB_SIZE}-byte fields"
    );
    bytes
        .chunks_exact(PUB_SIZE)
        .map(|chunk| {
            chunk
                .try_into()
                .expect("chunks_exact always returns PUB_SIZE bytes")
        })
        .collect()
}

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where T: pallet_verifiers::Config<Verifier<T>>)]
mod benchmarks {
    use super::*;

    benchmarking_utils!(Verifier<T>, crate::Config);

    #[benchmark]
    fn verify_proof_domain_1024() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_1024_PROOF,
            DOMAIN_1024_VERIFIER_INDEX,
            DOMAIN_1024_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_2048() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_2048_PROOF,
            DOMAIN_2048_VERIFIER_INDEX,
            DOMAIN_2048_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_4096() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_4096_PROOF,
            DOMAIN_4096_VERIFIER_INDEX,
            DOMAIN_4096_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_4096_pubs_64() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_4096_PUBS_64_PROOF,
            DOMAIN_4096_PUBS_64_VERIFIER_INDEX,
            DOMAIN_4096_PUBS_64_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_65536_pubs_64() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_65536_PUBS_64_PROOF,
            DOMAIN_65536_PUBS_64_VERIFIER_INDEX,
            DOMAIN_65536_PUBS_64_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_65536_recursive_3_pubs_64() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_65536_RECURSIVE_3_PUBS_64_PROOF,
            DOMAIN_65536_RECURSIVE_3_PUBS_64_VERIFIER_INDEX,
            DOMAIN_65536_RECURSIVE_3_PUBS_64_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_65536_lookup_recursive_3_pubs_64() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_65536_LOOKUP_RECURSIVE_3_PUBS_64_PROOF,
            DOMAIN_65536_LOOKUP_RECURSIVE_3_PUBS_64_VERIFIER_INDEX,
            DOMAIN_65536_LOOKUP_RECURSIVE_3_PUBS_64_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    #[benchmark]
    fn verify_proof_domain_65536_xor_lookup_recursive_3_pubs_64() {
        let (proof, vk, pubs) = benchmark_data::<T>(
            DOMAIN_65536_XOR_LOOKUP_RECURSIVE_3_PUBS_64_PROOF,
            DOMAIN_65536_XOR_LOOKUP_RECURSIVE_3_PUBS_64_VERIFIER_INDEX,
            DOMAIN_65536_XOR_LOOKUP_RECURSIVE_3_PUBS_64_PUBS,
        );

        let r;
        #[block]
        {
            r = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(r.is_ok());
    }

    impl_benchmark_test_suite!(Pallet, super::mock::test_ext(), super::mock::Test);
}

#[cfg(test)]
mod mock {
    use frame_support::{
        derive_impl, parameter_types,
        sp_runtime::{traits::IdentityLookup, BuildStorage},
        traits::{fungible::HoldConsideration, LinearStoragePrice},
    };
    use sp_core::{ConstU128, ConstU32};

    type Balance = u128;
    type AccountId = u64;

    frame_support::construct_runtime!(
        pub enum Test
        {
            System: frame_system,
            Balances: pallet_balances,
            CommonVerifiersPallet: pallet_verifiers::common,
            VerifierPallet: crate,
        }
    );

    impl crate::Config for Test {
        type MaxProofSize = ConstU32<262144>;
        type MaxPubs = ConstU32<64>;
        type MaxVkSize = ConstU32<65536>;
        type WeightInfo = ();
    }

    #[derive_impl(frame_system::config_preludes::SolochainDefaultConfig as frame_system::DefaultConfig)]
    impl frame_system::Config for Test {
        type Block = frame_system::mocking::MockBlockU32<Test>;
        type AccountId = AccountId;
        type AccountData = pallet_balances::AccountData<Balance>;
        type Lookup = IdentityLookup<Self::AccountId>;
    }

    parameter_types! {
        pub const BaseDeposit: Balance = 1;
        pub const PerByteDeposit: Balance = 2;
        pub const HoldReasonVkRegistration: RuntimeHoldReason = RuntimeHoldReason::CommonVerifiersPallet(pallet_verifiers::common::HoldReason::VkRegistration);
    }

    impl pallet_verifiers::Config<crate::Kimchi<Test>> for Test {
        type RuntimeEvent = RuntimeEvent;
        type OnProofVerified = ();
        type WeightInfo = crate::KimchiWeight<()>;
        type Ticket = HoldConsideration<
            AccountId,
            Balances,
            HoldReasonVkRegistration,
            LinearStoragePrice<BaseDeposit, PerByteDeposit, Balance>,
        >;
        type Currency = Balances;
    }

    impl pallet_balances::Config for Test {
        type RuntimeEvent = RuntimeEvent;
        type RuntimeHoldReason = RuntimeHoldReason;
        type RuntimeFreezeReason = RuntimeFreezeReason;
        type WeightInfo = ();
        type Balance = Balance;
        type DustRemoval = ();
        type ExistentialDeposit = ConstU128<1>;
        type AccountStore = System;
        type ReserveIdentifier = [u8; 8];
        type FreezeIdentifier = RuntimeFreezeReason;
        type MaxLocks = ConstU32<10>;
        type MaxReserves = ConstU32<10>;
        type MaxFreezes = ConstU32<10>;
        type DoneSlashHandler = ();
    }

    impl pallet_verifiers::common::Config for Test {
        type CommonWeightInfo = Test;
    }

    pub fn test_ext() -> sp_io::TestExternalities {
        let mut ext = sp_io::TestExternalities::from(
            frame_system::GenesisConfig::<Test>::default()
                .build_storage()
                .expect("mock genesis storage should build"),
        );
        ext.execute_with(|| System::set_block_number(1));
        ext
    }
}
