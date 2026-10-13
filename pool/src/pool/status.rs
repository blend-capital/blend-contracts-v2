use crate::{
    constants::SCALAR_7,
    dependencies::{BackstopClient, PoolBackstopData},
    storage, PoolError,
};
use sep_40_oracle::PriceFeedClient;
use soroban_sdk::{panic_with_error, Env};

/// Update the pool status based on the backstop module
#[allow(clippy::zero_prefixed_literal)]
#[allow(clippy::inconsistent_digit_grouping)]
pub fn execute_update_pool_status(e: &Env) -> u32 {
    let mut pool_config = storage::get_pool_config(e);
    if pool_config.status == 4 {
        panic_with_error!(e, PoolError::StatusNotAllowed);
    }

    // check the pool has met minimum backstop deposits
    let backstop_id = storage::get_backstop(e);
    let backstop_client = BackstopClient::new(e, &backstop_id);

    let pool_backstop_data = backstop_client.pool_data(&e.current_contract_address());
    let threshold = calc_pool_backstop_threshold(&pool_backstop_data);
    let mut met_threshold = true;
    if threshold < SCALAR_7 {
        met_threshold = false;
    }

    match pool_config.status {
        // Setup
        6 => {
            // Setup supersedes all other statuses
            panic_with_error!(e, PoolError::StatusNotAllowed);
        }
        // Admin on-ice
        2 => {
            if pool_backstop_data.q4w_pct >= 0_7500000 {
                // Q4W over 75% freezes the pool
                pool_config.status = 5;
            }
        }
        // Admin active
        0 => {
            if !met_threshold || pool_backstop_data.q4w_pct >= 0_5000000 {
                // Q4w over 50% or being under threshold puts the pool on-ice
                pool_config.status = 3;
            }
        }
        // Admin status isn't set
        _ => {
            if pool_backstop_data.q4w_pct >= 0_6000000 {
                // Q4w over 60% sets pool to Frozen
                pool_config.status = 5;
            } else if pool_backstop_data.q4w_pct >= 0_3000000 || !met_threshold {
                // Q4w over 30% sets pool to On-Ice
                pool_config.status = 3;
            } else {
                // Backstop is healthy and the pool is set to Active
                pool_config.status = 1;
            }
        }
    }
    storage::set_pool_config(e, &pool_config);
    pool_config.status
}

/// Admin set the pool status
#[allow(clippy::zero_prefixed_literal)]
#[allow(clippy::inconsistent_digit_grouping)]
pub fn execute_set_pool_status(e: &Env, pool_status: u32) {
    let mut pool_config = storage::get_pool_config(e);
    if pool_status == 4 {
        pool_config.status = 4;
        storage::set_pool_config(e, &pool_config);
        return;
    }
    if pool_config.status == 4 {
        panic_with_error!(e, PoolError::StatusNotAllowed);
    }

    // a pool leaving setup must have a 7 decimal oracle, which can't be changed afterwards
    if pool_config.status == 6
        && matches!(pool_status, 0 | 2 | 3)
        && PriceFeedClient::new(e, &pool_config.oracle).decimals() != 7
    {
        panic_with_error!(e, PoolError::InvalidPrice);
    }

    // check the pool has met minimum backstop deposits
    let backstop_id = storage::get_backstop(e);
    let backstop_client = BackstopClient::new(e, &backstop_id);

    let pool_backstop_data = backstop_client.pool_data(&e.current_contract_address());

    match pool_status {
        0 => {
            // Threshold must be met and q4w must be under 50% for the admin to set Active
            if calc_pool_backstop_threshold(&pool_backstop_data) < SCALAR_7
                || pool_backstop_data.q4w_pct >= 0_5000000
            {
                panic_with_error!(e, PoolError::StatusNotAllowed);
            }
            // Admin Active
            pool_config.status = 0;
        }
        2 => {
            // Q4w must be under 75% for admin to set On-Ice
            if pool_backstop_data.q4w_pct >= 0_7500000 {
                panic_with_error!(e, PoolError::StatusNotAllowed);
            }
            // Admin On-Ice
            pool_config.status = 2;
        }
        3 => {
            // Q4w must be under 75% for admin to set permissionless On-Ice
            if pool_backstop_data.q4w_pct >= 0_7500000 {
                panic_with_error!(e, PoolError::StatusNotAllowed);
            }
            // On-Ice
            pool_config.status = 3;
        }
        _ => {
            panic_with_error!(e, PoolError::BadRequest);
        }
    }
    storage::set_pool_config(e, &pool_config);
}

/// Calculate the threshold for the pool's backstop balance
///
/// Returns the threshold as a percentage^5 in SCALAR_7 points such that SCALAR_7 = 100%
/// NOTE: The result is the percentage^5 to simplify the calculation of the pools product constant.
///       Some useful results:
///         - greater than 1 = 100+%
///         - 1_0000000 = 100%
///         - 0_0000100 = ~10%
///         - 0_0000003 = ~5%
///         - 0_0000000 = ~0-4%
pub fn calc_pool_backstop_threshold(pool_backstop_data: &PoolBackstopData) -> i128 {
    // @dev: Calculation for pools product constant of underlying will often overflow i128
    //       so saturating mul is used. This is safe because the threshold is below i128::MAX and the
    //       protocol does not need to differentiate between pools over the threshold product constant.
    //       The calculation is:
    //        - Threshold % = (bal_blnd^4 * bal_usdc) / PC^5 such that PC is 100k
    let threshold_pc = 10_000_000_000_000_000_000_000_000i128; // 1e25 (100k^5)

    // floor balances to nearest full unit and calculate saturated pool product constant
    // and scale to SCALAR_7 to get final division result in SCALAR_7 points
    let bal_blnd = pool_backstop_data.blnd / SCALAR_7;
    let bal_usdc = pool_backstop_data.usdc / SCALAR_7;
    let saturating_pool_pc = bal_blnd
        .saturating_mul(bal_blnd)
        .saturating_mul(bal_blnd)
        .saturating_mul(bal_blnd)
        .saturating_mul(bal_usdc)
        .saturating_mul(SCALAR_7); // 10^7 * 10^7
    saturating_pool_pc / threshold_pc
}

#[cfg(test)]
mod tests {
    use crate::{
        storage::PoolConfig,
        testutils::{
            create_backstop, create_comet_lp_pool, create_mock_oracle, create_pool,
            create_token_contract,
        },
    };

    use super::*;
    use sep_40_oracle::testutils::Asset;
    use soroban_sdk::{testutils::Address as _, vec, Address, Symbol};

    #[test]
    fn test_set_pool_status_active() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 1,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 0);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, 0);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1204)")]
    fn test_set_pool_status_active_blocks_without_backstop_minimum() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens - under limit
        blnd_client.mint(&samwise, &400_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &10_001_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &40_000_0000000,
            &vec![&e, 400_001_0000000, 10_001_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &20_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 1,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 0);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1204)")]
    fn test_set_pool_status_active_blocks_with_too_high_q4w() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &30_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 2,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 0);
        });
    }
    #[test]
    fn test_set_pool_status_on_ice() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 1,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 2);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, 2);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1204)")]
    fn test_set_pool_status_admin_on_ice_blocks_with_too_high_q4w() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &40_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 5,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 2);
        });
    }
    #[test]
    #[should_panic(expected = "Error(Contract, #1204)")]
    fn test_set_pool_status_backstop_on_ice_blocks_with_too_high_q4w() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let (oracle_id, oracle_client) = create_mock_oracle(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);
        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![&e, Asset::Stellar(Address::generate(&e))],
            &7,
            &300,
        );

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &40_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 6,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 3);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1210)")]
    fn test_set_pool_status_setup_blocks_with_invalid_oracle_decimals() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);
        let (oracle_id, oracle_client) = create_mock_oracle(&e);
        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![&e, Asset::Stellar(Address::generate(&e))],
            &8,
            &300,
        );

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 6,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 0);
        });
    }
    #[test]
    fn test_set_pool_status_frozen() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 1,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 4);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, 4);
        });
    }
    #[test]
    #[should_panic(expected = "Error(Contract, #1200)")]
    fn test_set_non_admin_pool_status_panics() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 2,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 1);
        });
    }

    #[test]
    fn test_update_pool_status_active() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 3,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 1);
        });
    }

    #[test]
    fn test_update_pool_status_admin_set_no_changes() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 0);
        });
    }

    #[test]
    fn test_update_pool_status_on_ice_tokens() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens - under limit
        blnd_client.mint(&samwise, &400_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &10_001_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &40_000_0000000,
            &vec![&e, 400_001_0000000, 10_001_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &20_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 1,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 3);
        });
    }

    #[test]
    fn test_update_pool_status_on_ice_30_q4w() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &15_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 1,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 3);
        });
    }

    #[test]
    fn test_update_pool_status_on_ice_30_q4w_admin_active() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &15_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 0);
        });
    }

    #[test]
    fn test_update_pool_status_on_ice_50_q4w_admin_active() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &25_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 3);
        });
    }

    #[test]
    fn test_update_pool_status_frozen() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &30_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 1,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 5);
        });
    }
    #[test]
    fn test_update_pool_status_frozen_admin_on_ice() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &30_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 2,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 2);
        });
    }

    #[test]
    fn test_update_pool_status_frozen_75_q4w() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &40_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 2,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            let status = execute_update_pool_status(&e);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, status);
            assert_eq!(status, 5);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1204)")]
    fn test_update_pool_status_admin_frozen() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 4,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_update_pool_status(&e);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1204)")]
    fn test_update_pool_status_setup() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();
        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 6,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_update_pool_status(&e);
        });
    }

    #[test]
    fn test_admin_update_pool_status_unfreeze() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();

        let pool_id = create_pool(&e);
        let oracle_id = Address::generate(&e);

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd, blnd_client) = create_token_contract(&e, &bombadil);
        let (usdc, usdc_client) = create_token_contract(&e, &bombadil);
        let (lp_token, lp_token_client) = create_comet_lp_pool(&e, &bombadil, &blnd, &usdc);
        let (_, backstop_client) = create_backstop(&e, &pool_id, &lp_token, &usdc, &blnd);

        // mint lp tokens
        blnd_client.mint(&samwise, &500_001_0000000);
        blnd_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        usdc_client.mint(&samwise, &12_501_0000000);
        usdc_client.approve(&samwise, &lp_token, &i128::MAX, &99999);
        lp_token_client.join_pool(
            &50_000_0000000,
            &vec![&e, 500_001_0000000, 12_501_0000000],
            &samwise,
        );
        backstop_client.deposit(&samwise, &pool_id, &50_000_0000000);
        backstop_client.queue_withdrawal(&samwise, &pool_id, &12_500_0000000);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 0,
            bstop_rate: 0,
            status: 5,
            max_positions: 4,
        };
        e.as_contract(&pool_id, || {
            storage::set_admin(&e, &bombadil);
            storage::set_pool_config(&e, &pool_config);

            execute_set_pool_status(&e, 0);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.status, 0);
        });
    }

    #[test]
    fn test_calc_pool_backstop_threshold() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();

        let pool_backstop_data = PoolBackstopData {
            blnd: 175_000_0000000,
            q4w_pct: 0,
            tokens: 20_000_0000000,
            shares: 50_000_0000000,
            usdc: 6_500_0000000,
            token_spot_price: 0_5000000,
        }; // ~90.5% threshold

        let result = calc_pool_backstop_threshold(&pool_backstop_data);
        assert_eq!(result, 0_6096289);
    }

    #[test]
    fn test_calc_pool_backstop_threshold_too_small() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();

        let pool_backstop_data = PoolBackstopData {
            blnd: 5_000_0000000,
            q4w_pct: 0,
            tokens: 500_0000000,
            shares: 1_000_0000000,
            usdc: 1_000_0000000,
            token_spot_price: 0_5000000,
        }; // ~3.6% threshold

        let result = calc_pool_backstop_threshold(&pool_backstop_data);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_calc_pool_backstop_threshold_over() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();

        let pool_backstop_data = PoolBackstopData {
            blnd: 200_000_0000000,
            q4w_pct: 0,
            tokens: 15_000_0000000,
            shares: 1_000_0000000,
            usdc: 6_250_0000000,
            token_spot_price: 0_5000000,
        }; // 100% threshold

        let result = calc_pool_backstop_threshold(&pool_backstop_data);
        assert_eq!(result, 1_0000000);
    }

    #[test]
    fn test_calc_pool_backstop_threshold_saturates() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();

        let pool_backstop_data = PoolBackstopData {
            blnd: 50_000_000_0000000,
            q4w_pct: 0,
            tokens: 999_999_0000000,
            shares: 999_999_0000000,
            usdc: 10_000_000_0000000,
            token_spot_price: 0_5000000,
        }; // 362x threshold

        let result = calc_pool_backstop_threshold(&pool_backstop_data);
        assert_eq!(result, 1701411_8346046);
    }

    #[test]
    fn test_calc_pool_backstop_threshold_10_percent() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();

        let pool_backstop_data = PoolBackstopData {
            blnd: 20_000_0000000,
            q4w_pct: 0,
            tokens: 1_000_0000000,
            shares: 1_000_0000000,
            usdc: 625_0000000,
            token_spot_price: 0_5000000,
        }; // 10% threshold

        let result = calc_pool_backstop_threshold(&pool_backstop_data);
        assert_eq!(result, 0_0000100);
    }

    #[test]
    fn test_calc_pool_backstop_threshold_5pct() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();

        let pool_backstop_data = PoolBackstopData {
            blnd: 10_000_0000000,
            q4w_pct: 0,
            tokens: 999_999_0000000,
            shares: 999_999_0000000,
            usdc: 312_5000000,
            token_spot_price: 0_5000000,
        }; // 5% threshold

        let result = calc_pool_backstop_threshold(&pool_backstop_data);
        assert_eq!(result, 0_0000003);
    }
}
