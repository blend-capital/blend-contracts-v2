//! Methods for distributing backstop emissions to depositors

use cast::i128;
use soroban_fixed_point_math::FixedPoint;
use soroban_sdk::{panic_with_error, unwrap::UnwrapOptimized, Address, Env};

use crate::{
    backstop::{PoolBalance, UserBalance},
    constants::{SCALAR_14, SCALAR_7},
    require_nonnegative,
    storage::{self, BackstopEmissionData, UserEmissionData},
    BackstopError,
};

/// Update the backstop emissions index for the user and pool
pub fn update_emissions(
    e: &Env,
    pool_id: &Address,
    pool_balance: &PoolBalance,
    user_id: &Address,
    user_balance: &UserBalance,
) {
    if let Some(emis_data) = update_emission_data(e, pool_id, pool_balance) {
        update_user_emissions(e, pool_id, user_id, &emis_data, user_balance, false);
    }
}

/// Update for claiming emissions for a user and pool
///
/// DOES NOT SEND CLAIMED TOKENS TO THE USER. The caller
/// is expected to handle sending the tokens once all claimed pools
/// have been processed.
///
/// Returns the number of tokens that need to be transferred to `user`
///
/// Panics if the pool's backstop never had emissions configured
pub(super) fn claim_emissions(
    e: &Env,
    pool_id: &Address,
    pool_balance: &PoolBalance,
    user_id: &Address,
    user_balance: &UserBalance,
) -> i128 {
    if let Some(emis_data) = update_emission_data(e, pool_id, pool_balance) {
        update_user_emissions(e, pool_id, user_id, &emis_data, user_balance, true)
    } else {
        panic_with_error!(e, BackstopError::BadRequest)
    }
}

/// Update the backstop emissions index for deposits
pub fn update_emission_data(
    e: &Env,
    pool_id: &Address,
    pool_balance: &PoolBalance,
) -> Option<BackstopEmissionData> {
    match storage::get_backstop_emis_data(e, pool_id) {
        Some(emis_data) => {
            if emis_data.last_time >= emis_data.expiration
                || e.ledger().timestamp() == emis_data.last_time
                || emis_data.eps == 0
                || pool_balance.shares == 0
            {
                // emis_data already updated or expired
                return Some(emis_data);
            }

            let max_timestamp = if e.ledger().timestamp() > emis_data.expiration {
                emis_data.expiration
            } else {
                e.ledger().timestamp()
            };

            let unqueued_shares = pool_balance.shares - pool_balance.q4w;
            require_nonnegative(e, unqueued_shares);
            let additional_idx: i128;
            if unqueued_shares == 0 {
                // all shares q4w, omit emissions
                additional_idx = 0;
            } else {
                // Eps is in 14 decimals and needs to be converted to 7 decimals to match emission token decimals
                additional_idx = (i128(max_timestamp - emis_data.last_time) * i128(emis_data.eps))
                    .fixed_div_floor(unqueued_shares, SCALAR_7)
                    .unwrap_optimized();
            }
            let new_data = BackstopEmissionData {
                eps: emis_data.eps,
                expiration: emis_data.expiration,
                index: additional_idx + emis_data.index,
                last_time: e.ledger().timestamp(),
            };

            storage::set_backstop_emis_data(e, pool_id, &new_data);
            Some(new_data)
        }
        None => return None, // no emission exist, no update is required
    }
}

/// Update the user's emissions. If `to_claim` is true, the user's accrued emissions will be returned and
/// a value of zero will be stored to the ledger.
///
/// ### Returns
/// The number of emitted tokens the caller needs to send to the user
fn update_user_emissions(
    e: &Env,
    pool: &Address,
    user: &Address,
    emis_data: &BackstopEmissionData,
    user_balance: &UserBalance,
    to_claim: bool,
) -> i128 {
    if let Some(user_data) = storage::get_user_emis_data(e, pool, user) {
        if user_data.index != emis_data.index || to_claim {
            let mut accrual = user_data.accrued;
            if user_balance.shares != 0 {
                let delta_index = emis_data.index - user_data.index;
                require_nonnegative(e, delta_index);
                let to_accrue = (user_balance.shares)
                    .fixed_mul_floor(delta_index, SCALAR_14)
                    .unwrap_optimized();
                accrual += to_accrue;
            }
            return set_user_emissions(e, pool, user, emis_data.index, accrual, to_claim);
        }
        // no accrual occured and no claim requested
        return 0;
    } else if user_balance.shares == 0 {
        // first time the user registered an action with the asset since emissions were added
        return set_user_emissions(e, pool, user, emis_data.index, 0, to_claim);
    } else {
        // user had tokens before emissions began, they are due any historical emissions
        let to_accrue = user_balance
            .shares
            .fixed_mul_floor(emis_data.index, SCALAR_14)
            .unwrap_optimized();
        return set_user_emissions(e, pool, user, emis_data.index, to_accrue, to_claim);
    }
}

fn set_user_emissions(
    e: &Env,
    pool_id: &Address,
    user: &Address,
    index: i128,
    accrued: i128,
    to_claim: bool,
) -> i128 {
    if to_claim {
        storage::set_user_emis_data(e, pool_id, user, &UserEmissionData { index, accrued: 0 });
        accrued
    } else {
        storage::set_user_emis_data(e, pool_id, user, &UserEmissionData { index, accrued });
        0
    }
}

#[cfg(test)]
mod tests {
    use crate::{testutils::create_backstop, Q4W};

    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        vec,
    };

    /********** update_emissions **********/

    #[test]
    fn test_update_emissions() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1713139200,
        };
        let user_emissions_data = UserEmissionData {
            index: 111110000000,
            accrued: 3,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);
            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);
            storage::set_user_emis_data(&e, &pool_1, &samwise, &user_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            storage::set_pool_balance(&e, &pool_1, &pool_balance);
            let user_balance = UserBalance {
                shares: 9_0000000,
                q4w: vec![&e],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);

            let new_backstop_data = storage::get_backstop_emis_data(&e, &pool_1).unwrap_optimized();
            let new_user_data =
                storage::get_user_emis_data(&e, &pool_1, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_data.last_time, block_timestamp);
            assert_eq!(new_backstop_data.index, 82488886666666);
            assert_eq!(new_user_data.accrued, 7_4140001);
            assert_eq!(new_user_data.index, 82488886666666);
        });
    }

    #[test]
    fn test_update_emissions_no_data() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            let user_balance = UserBalance {
                shares: 9_0000000,
                q4w: vec![&e],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);

            let new_backstop_data = storage::get_backstop_emis_data(&e, &pool_1);
            let new_user_data = storage::get_user_emis_data(&e, &pool_1, &samwise);
            assert!(new_backstop_data.is_none());
            assert!(new_user_data.is_none());
        });
    }

    #[test]
    fn test_update_emissions_first_action() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 12345;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_04200000000000,
            index: 222220000000,
            last_time: 1713139200,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            let user_balance = UserBalance {
                shares: 0,
                q4w: vec![&e],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);

            let new_backstop_data = storage::get_backstop_emis_data(&e, &pool_1).unwrap_optimized();
            let new_user_data =
                storage::get_user_emis_data(&e, &pool_1, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_data.last_time, block_timestamp);
            assert_eq!(new_backstop_data.index, 345882220000000);
            assert_eq!(new_user_data.accrued, 0);
            assert_eq!(new_user_data.index, 345882220000000);
        });
    }

    #[test]
    fn test_update_emissions_config_set_after_user() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 12345;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_04200000000000,
            index: 0,
            last_time: 1713139200,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            let user_balance = UserBalance {
                shares: 9_0000000,
                q4w: vec![&e],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);

            let new_backstop_data = storage::get_backstop_emis_data(&e, &pool_1).unwrap_optimized();
            let new_user_data =
                storage::get_user_emis_data(&e, &pool_1, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_data.last_time, block_timestamp);
            assert_eq!(new_backstop_data.index, 345660000000000);
            assert_eq!(new_user_data.accrued, 31_1094000);
            assert_eq!(new_user_data.index, 345660000000000);
        });
    }

    #[test]
    fn test_update_emissions_q4w_not_counted() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1713139200,
        };
        let user_emissions_data = UserEmissionData {
            index: 111110000000,
            accrued: 3,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);
            storage::set_user_emis_data(&e, &pool_1, &samwise, &user_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 4_5000000,
            };
            let q4w: Q4W = Q4W {
                amount: (4_5000000),
                exp: (5000),
            };
            let user_balance = UserBalance {
                shares: 4_5000000,
                q4w: vec![&e, q4w],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);

            let new_backstop_data = storage::get_backstop_emis_data(&e, &pool_1).unwrap_optimized();
            let new_user_data =
                storage::get_user_emis_data(&e, &pool_1, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_data.last_time, block_timestamp);
            assert_eq!(new_backstop_data.index, 85033216563573);
            assert_eq!(new_user_data.accrued, 38214950);
            assert_eq!(new_user_data.index, 85033216563573);
        });
    }

    #[test]
    fn test_update_emissions_fully_q4w_emissions_lost() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1713139200,
        };
        let user_emissions_data = UserEmissionData {
            index: 111110000000,
            accrued: 3,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);
            storage::set_user_emis_data(&e, &pool_1, &samwise, &user_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 150_0000000,
            };
            let q4w: Q4W = Q4W {
                amount: (150_0000000),
                exp: (5000),
            };
            let user_balance = UserBalance {
                shares: 4_5000000,
                q4w: vec![&e, q4w],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);

            let new_backstop_data = storage::get_backstop_emis_data(&e, &pool_1).unwrap_optimized();
            let new_user_data =
                storage::get_user_emis_data(&e, &pool_1, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_data.last_time, block_timestamp);
            assert_eq!(new_backstop_data.index, backstop_emissions_data.index);
            assert_eq!(new_user_data.accrued, 50002);
            assert_eq!(new_user_data.index, backstop_emissions_data.index);
        });
    }

    #[test]
    fn test_claim_emissions() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1713139200,
        };
        let user_emissions_data = UserEmissionData {
            index: 111110000000,
            accrued: 3,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);
            storage::set_user_emis_data(&e, &pool_1, &samwise, &user_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            storage::set_pool_balance(&e, &pool_1, &pool_balance);
            let user_balance = UserBalance {
                shares: 9_0000000,
                q4w: vec![&e],
            };

            let result = claim_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);

            let new_backstop_data = storage::get_backstop_emis_data(&e, &pool_1).unwrap_optimized();
            let new_user_data =
                storage::get_user_emis_data(&e, &pool_1, &samwise).unwrap_optimized();
            assert_eq!(result, 7_4140001);
            assert_eq!(new_backstop_data.last_time, block_timestamp);
            assert_eq!(new_backstop_data.index, 82488886666666);
            assert_eq!(new_user_data.accrued, 0);
            assert_eq!(new_user_data.index, 82488886666666);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1000)")]
    fn test_claim_emissions_no_config() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            let user_balance = UserBalance {
                shares: 9_0000000,
                q4w: vec![&e],
            };

            claim_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);
        });
    }

    // @dev: The below tests should be impossible states to reach, but are left
    //       in to ensure any bad state does not result in incorrect emissions.

    #[test]
    #[should_panic(expected = "Error(Contract, #8)")]
    fn test_update_emissions_more_q4w_than_shares_panics() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 22222,
            last_time: 1713139200,
        };
        let user_emissions_data = UserEmissionData {
            index: 11111,
            accrued: 3,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);
            storage::set_user_emis_data(&e, &pool_1, &samwise, &user_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 150_0000001,
            };
            let q4w: Q4W = Q4W {
                amount: (4_5000000),
                exp: (5000),
            };
            let user_balance = UserBalance {
                shares: 4_5000000,
                q4w: vec![&e, q4w],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);
        });
    }

    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn test_update_emissions_negative_time_dif() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 22222,
            last_time: block_timestamp + 1,
        };
        let user_emissions_data = UserEmissionData {
            index: 11111,
            accrued: 3,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);
            storage::set_user_emis_data(&e, &pool_1, &samwise, &user_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            let user_balance = UserBalance {
                shares: 4_5000000,
                q4w: vec![&e],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #8)")]
    fn test_update_emissions_negative_user_index() {
        let e = Env::default();
        let block_timestamp = 1713139200 + 1234;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_id = create_backstop(&e);
        let pool_1 = Address::generate(&e);
        let samwise = Address::generate(&e);

        let backstop_emissions_data = BackstopEmissionData {
            expiration: 1713139200 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1713139200,
        };
        let user_emissions_data = UserEmissionData {
            index: 345660000000000 + 1,
            accrued: 3,
        };
        e.as_contract(&backstop_id, || {
            storage::set_last_distribution_time(&e, &1713139200);

            storage::set_backstop_emis_data(&e, &pool_1, &backstop_emissions_data);
            storage::set_user_emis_data(&e, &pool_1, &samwise, &user_emissions_data);

            let pool_balance = PoolBalance {
                shares: 150_0000000,
                tokens: 200_0000000,
                q4w: 0,
            };
            let user_balance = UserBalance {
                shares: 4_5000000,
                q4w: vec![&e],
            };

            update_emissions(&e, &pool_1, &pool_balance, &samwise, &user_balance);
        });
    }
}
