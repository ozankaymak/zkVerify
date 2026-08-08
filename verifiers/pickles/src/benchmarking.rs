// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime-benchmarks")]

use crate::{Pickles as Verifier, PicklesProfileId, Proof, Pubs, Vk};
use alloc::vec;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use pallet_verifiers::traits::Verifier as _;
use pallet_verifiers::{benchmarking_utils, VkOrHash};

pub trait Config: crate::Config {}
pub struct Pallet<T: Config>(crate::Pallet<T>);
impl<T: crate::Config> Config for T {}
pub type Call<T> = pallet_verifiers::Call<T, Verifier<T>>;

const BENCH_PROOF: &[u8] = include_bytes!("resources/width2/proof.bin");
const BENCH_VERIFIER_INDEX: &[u8] = include_bytes!("resources/width2/verifier-index.bin");

fn benchmark_data<T: crate::Config>() -> (Proof, Vk<T>, Pubs) {
    let mut input = [0_u8; crate::FIELD_SIZE];
    input[0] = 18;
    let mut output = [0_u8; crate::FIELD_SIZE];
    output[0] = 19;
    (
        BENCH_PROOF.to_vec(),
        Vk::new(BENCH_VERIFIER_INDEX.to_vec(), PicklesProfileId::PicklesV1),
        Pubs {
            public_input: vec![input],
            public_output: vec![output],
        },
    )
}

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where T: pallet_verifiers::Config<Verifier<T>>)]
mod benchmarks {
    use super::*;

    benchmarking_utils!(Verifier<T>, crate::Config);

    #[benchmark]
    fn verify_proof() {
        let (proof, vk, pubs) = benchmark_data::<T>();
        let result;
        #[block]
        {
            result = do_verify_proof::<T>(&vk, &proof, &pubs)
        };
        assert!(result.is_ok());
    }

    #[benchmark]
    fn get_vk() {
        let (_, vk, _) = benchmark_data::<T>();
        let hash = sp_core::H256::repeat_byte(2);
        insert_vk_anonymous::<T>(vk, hash);
        let result;
        #[block]
        {
            result = do_get_vk::<T>(&hash)
        };
        assert!(result.is_some());
    }

    #[benchmark]
    fn validate_vk() {
        let (_, vk, _) = benchmark_data::<T>();
        let result;
        #[block]
        {
            result = do_validate_vk::<T>(&vk)
        };
        assert!(result.is_ok());
    }

    #[benchmark]
    fn compute_statement_hash() {
        let (proof, vk, pubs) = benchmark_data::<T>();
        let vk = VkOrHash::Vk(vk.into());
        #[block]
        {
            do_compute_statement_hash::<T>(&vk, &proof, &pubs);
        }
    }

    #[benchmark]
    fn register_vk() {
        let caller = funded_account::<T>();
        let (_, vk, _) = benchmark_data::<T>();
        #[extrinsic_call]
        register_vk(RawOrigin::Signed(caller), vk.clone().into());
        assert!(do_get_vk::<T>(&do_vk_hash::<T>(&vk)).is_some());
    }

    #[benchmark]
    fn unregister_vk() {
        let caller: T::AccountId = funded_account::<T>();
        let hash = sp_core::H256::repeat_byte(2);
        let (_, vk, _) = benchmark_data::<T>();
        insert_vk::<T>(caller.clone(), vk, hash);
        #[extrinsic_call]
        unregister_vk(RawOrigin::Signed(caller), hash);
        assert!(do_get_vk::<T>(&hash).is_none());
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
        pub enum Test {
            System: frame_system,
            Balances: pallet_balances,
            CommonVerifiersPallet: pallet_verifiers::common,
            VerifierPallet: crate,
        }
    );

    impl crate::Config for Test {
        type MaxProofSize = ConstU32<65_536>;
        type MaxPubs = ConstU32<1_024>;
        type MaxVkSize = ConstU32<4_096>;
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

    impl pallet_verifiers::Config<crate::Pickles<Test>> for Test {
        type OnProofVerified = ();
        type WeightInfo = crate::PicklesWeight<()>;
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
        sp_io::TestExternalities::from(
            frame_system::GenesisConfig::<Test>::default()
                .build_storage()
                .unwrap(),
        )
    }
}
