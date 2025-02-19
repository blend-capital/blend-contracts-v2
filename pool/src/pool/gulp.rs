use sep_41_token::TokenClient;
use soroban_sdk::{panic_with_error, Address, Env};

use crate::{storage, PoolError};

use super::Reserve;

/// Updates the reserve's B token supply to match the pool's asset balance
///
/// ### Arguments
/// * `asset` - The address of the asset to gulp
///
/// ### Returns
/// * (i128, i128) - The token delta in the pool's asset balance and the reserve's B token supply, the new b rate
pub fn execute_gulp(e: &Env, asset: &Address) -> (i128, i128) {
    let pool_config = storage::get_pool_config(e);
    let mut reserve = Reserve::load(e, &pool_config, asset);
    let pool_token_balance = TokenClient::new(e, asset).balance(&e.current_contract_address());
    let reserve_token_balance =
        reserve.total_supply(e) + reserve.data.backstop_credit - reserve.total_liabilities(e);

    // Rejects if there's less than 1 total token in the reserve
    if reserve.data.b_supply < reserve.scalar {
        panic_with_error!(e, PoolError::GulpReserveTooLow);
    }

    let token_balance_delta = pool_token_balance - reserve_token_balance;

    let pre_gulp_b_rate = reserve.data.b_rate;
    reserve.gulp(e, pool_config.bstop_rate, token_balance_delta);

    // If the reserve's b_rate hasn't changed the token delta is not significant
    if pre_gulp_b_rate == reserve.data.b_rate {
        return (0, pre_gulp_b_rate);
    }

    reserve.store(e);
    return (token_balance_delta, reserve.data.b_rate);
}

#[cfg(test)]
mod tests {
    use crate::constants::SCALAR_7;
    use crate::pool::execute_gulp;
    use crate::storage::{self, PoolConfig};
    use crate::testutils;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Address, Env,
    };

    #[test]
    fn test_execute_gulp() {
        let e = Env::default();
        e.mock_all_auths();
        e.ledger().set(LedgerInfo {
            timestamp: 100,
            protocol_version: 22,
            sequence_number: 1234,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        let bombadil = Address::generate(&e);
        let pool = testutils::create_pool(&e);
        let (oracle, _) = testutils::create_mock_oracle(&e);

        let (underlying, underlying_client) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, mut reserve_data) = testutils::default_reserve_meta();
        reserve_data.b_rate = 1_000_000_000_000;
        reserve_data.d_rate = 1_000_000_000_000;
        reserve_data.d_supply = 500 * SCALAR_7;
        reserve_data.b_supply = 1000 * SCALAR_7;
        reserve_data.backstop_credit = 0;
        reserve_data.last_time = 100;
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        let additional_tokens = 10 * SCALAR_7;
        underlying_client.mint(&pool, &additional_tokens);
        e.as_contract(&pool, || {
            let pool_config = PoolConfig {
                oracle,
                bstop_rate: 0_1000000,
                status: 0,
                max_positions: 4,
            };
            storage::set_pool_config(&e, &pool_config);

            let (token_delta_result, new_b_rate) = execute_gulp(&e, &underlying);
            assert_eq!(token_delta_result, additional_tokens);
            assert_eq!(new_b_rate, 1_009_000_000_000);

            let new_reserve_data = storage::get_res_data(&e, &underlying);
            assert_eq!(new_reserve_data.b_rate, new_b_rate);
            assert_eq!(new_reserve_data.last_time, 100);
            assert_eq!(new_reserve_data.backstop_credit, 1_0000000);
        });
    }

    #[test]
    fn test_execute_gulp_accrues_interest() {
        let e = Env::default();
        e.mock_all_auths();
        e.ledger().set(LedgerInfo {
            timestamp: 100,
            protocol_version: 22,
            sequence_number: 1234,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        let bombadil = Address::generate(&e);
        let pool = testutils::create_pool(&e);
        let (oracle, _) = testutils::create_mock_oracle(&e);

        let (underlying, underlying_client) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, mut reserve_data) = testutils::default_reserve_meta();
        reserve_data.b_rate = 1_000_000_000_000;
        reserve_data.d_rate = 1_000_000_000_000;
        reserve_data.d_supply = 500 * SCALAR_7;
        reserve_data.b_supply = 1000 * SCALAR_7;
        reserve_data.backstop_credit = 0;
        reserve_data.last_time = 0;
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        let additional_tokens = 10 * SCALAR_7;
        underlying_client.mint(&pool, &additional_tokens);
        e.as_contract(&pool, || {
            let pool_config = PoolConfig {
                oracle,
                bstop_rate: 0_1000000,
                status: 0,
                max_positions: 4,
            };
            storage::set_pool_config(&e, &pool_config);

            let (token_delta_result, new_b_rate) = execute_gulp(&e, &underlying);
            assert_eq!(token_delta_result, additional_tokens);
            assert_eq!(new_b_rate, 1_009_000_062_000);

            let new_reserve_data = storage::get_res_data(&e, &underlying);
            assert_eq!(new_reserve_data.b_rate, new_b_rate);
            assert_eq!(new_reserve_data.last_time, 100);
            assert_eq!(new_reserve_data.backstop_credit, 1_0000000 + 68);
        });
    }

    #[test]
    fn test_execute_gulp_zero_delta_skips() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();
        e.ledger().set(LedgerInfo {
            timestamp: 100,
            protocol_version: 22,
            sequence_number: 1234,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        let bombadil = Address::generate(&e);
        let pool = testutils::create_pool(&e);
        let (oracle, _) = testutils::create_mock_oracle(&e);

        let (underlying, _) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, mut reserve_data) = testutils::default_reserve_meta();
        reserve_data.b_rate = 1_000_000_000_000;
        reserve_data.d_rate = 1_000_000_000_000;
        reserve_data.d_supply = 500 * SCALAR_7;
        reserve_data.b_supply = 1000 * SCALAR_7;
        reserve_data.backstop_credit = 0;
        reserve_data.last_time = 0;
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        e.as_contract(&pool, || {
            let pool_config = PoolConfig {
                oracle,
                bstop_rate: 0_1000000,
                status: 0,
                max_positions: 4,
            };
            storage::set_pool_config(&e, &pool_config);

            let (token_delta_result, new_b_rate) = execute_gulp(&e, &underlying);
            assert_eq!(token_delta_result, 0);
            assert_eq!(new_b_rate, 1_000_000_062_000);

            // data not set
            let new_reserve_data = storage::get_res_data(&e, &underlying);
            assert_eq!(new_reserve_data.b_rate, 1_000_000_000_000);
            assert_eq!(new_reserve_data.last_time, 0);
            assert_eq!(new_reserve_data.backstop_credit, 0);
        });
    }

    #[test]
    fn test_execute_gulp_requires_b_rate_change() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        e.ledger().set(LedgerInfo {
            timestamp: 100,
            protocol_version: 22,
            sequence_number: 1234,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        let bombadil = Address::generate(&e);
        let pool = testutils::create_pool(&e);
        let (oracle, _) = testutils::create_mock_oracle(&e);

        let (underlying, underlying_client) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, mut reserve_data) = testutils::default_reserve_meta();
        reserve_data.b_rate = 1_623_456_890_000;
        reserve_data.d_rate = 1_323_456_890_000;
        reserve_data.d_supply = 990_711 * SCALAR_7;
        reserve_data.b_supply = 123_493_400 * SCALAR_7;
        reserve_data.last_time = 0;
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        underlying_client.mint(&pool, &1000);
        e.as_contract(&pool, || {
            let pool_config = PoolConfig {
                oracle,
                bstop_rate: 0_1000000,
                status: 0,
                max_positions: 4,
            };
            storage::set_pool_config(&e, &pool_config);

            let (token_delta_result, new_b_rate) = execute_gulp(&e, &underlying);
            assert_eq!(token_delta_result, 0);
            assert_eq!(new_b_rate, 1_623_456_890_316); // from interest
                                                       // validate not stored
            let new_reserve_data = storage::get_res_data(&e, &underlying);
            assert_eq!(new_reserve_data.backstop_credit, 0);
            assert_eq!(new_reserve_data.b_rate, reserve_data.b_rate);
            assert_eq!(new_reserve_data.last_time, 0);
        });
    }

    #[test]
    #[should_panic(expected = "1224")]
    fn test_execute_gulp_fails_if_less_than_scalar() {
        let e = Env::default();
        e.mock_all_auths();
        e.ledger().set(LedgerInfo {
            timestamp: 100,
            protocol_version: 22,
            sequence_number: 1234,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        let bombadil = Address::generate(&e);
        let pool = testutils::create_pool(&e);
        let (oracle, _) = testutils::create_mock_oracle(&e);

        let (underlying, underlying_client) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, mut reserve_data) = testutils::default_reserve_meta();
        reserve_data.b_rate = 1_000_000_000_000;
        reserve_data.d_rate = 1_000_000_000_000;
        reserve_data.d_supply = 0;
        reserve_data.b_supply = SCALAR_7 / 2; // Less than 1 full token
        reserve_data.backstop_credit = 0;
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        e.as_contract(&pool, || {
            let pool_config = PoolConfig {
                oracle,
                bstop_rate: 0_1000000,
                status: 0,
                max_positions: 4,
            };
            storage::set_pool_config(&e, &pool_config);

            let (token_delta, b_rate) = execute_gulp(&e, &underlying);
            assert_eq!(token_delta, 0);
            assert_eq!(b_rate, reserve_data.b_rate);
        });
    }
}
