#![cfg(test)]

use std::i64;

use pool::{PoolClient, Request, RequestType, ReserveConfig};
use sep_41_token::testutils::MockTokenClient;
use soroban_sdk::{testutils::Address as _, vec, Address, String};
use test_suites::{
    assertions::assert_approx_eq_abs,
    test_fixture::{TestFixture, TokenIndex, SCALAR_12, SCALAR_7},
};

/// Test interest is accrued correctly over time
#[test]
fn test_pool_interest() {
    let mut fixture = TestFixture::create(false);

    let whale = Address::generate(&fixture.env);
    let samwise = Address::generate(&fixture.env);

    // Create two fixed-rate reserves with zero backstop take.
    fixture.create_pool(String::from_str(&fixture.env, "Teapot"), 0, 6, 0);
    let pool_client = PoolClient::new(&fixture.env, &fixture.pools[0].pool.address);

    // XLM - 10% fixed rate
    let xlm_client = MockTokenClient::new(&fixture.env, &fixture.tokens[TokenIndex::XLM].address);
    let xlm_config = ReserveConfig {
        c_factor: 900_0000,
        decimals: 7,
        index: 0,
        l_factor: 900_0000,
        max_util: 0_950_0000,
        reactivity: 0,
        r_base: 100_0000,
        r_one: 0,
        r_two: 0,
        r_three: 0,
        util: 50,
        supply_cap: i64::MAX as i128,
        min_position: 0,
        enabled: true,
    };
    fixture.create_pool_reserve(0, TokenIndex::XLM, &xlm_config);

    // STABLE - 10% fixed rate
    let stable_client =
        MockTokenClient::new(&fixture.env, &fixture.tokens[TokenIndex::STABLE].address);
    let stable_config = ReserveConfig {
        c_factor: 900_0000,
        decimals: 7,
        index: 1,
        l_factor: 900_0000,
        max_util: 0_950_0000,
        reactivity: 0,
        r_base: 100_0000,
        r_one: 0,
        r_two: 0,
        r_three: 0,
        util: 50,
        supply_cap: i64::MAX as i128,
        min_position: 0,
        enabled: true,
    };
    fixture.create_pool_reserve(0, TokenIndex::STABLE, &stable_config);

    // setup backstop and update pool status
    fixture.tokens[TokenIndex::BLND].mint(&whale, &(500_100 * SCALAR_7));
    fixture.tokens[TokenIndex::USDC].mint(&whale, &(12_600 * SCALAR_7));
    fixture.lp.join_pool(
        &(50_000 * SCALAR_7),
        &vec![&fixture.env, 500_100 * SCALAR_7, 12_600 * SCALAR_7],
        &whale,
    );
    fixture
        .backstop
        .deposit(&whale, &pool_client.address, &(50_000 * SCALAR_7));
    pool_client.set_status(&0);
    fixture.jump_with_sequence(60);

    /*
     * Deposit into pool
     * -> whale borrow from pool to return to 50% util rate
     */

    // initialize pool with 50% util rate
    // note - stable is 6 decimals, so these numbers are 10x higher than XLM
    let whale_deposit = 1_000_000 * SCALAR_7;
    xlm_client.mint(&whale, &whale_deposit);
    stable_client.mint(&whale, &whale_deposit);

    let starting_deposit = 1_000 * SCALAR_7;
    xlm_client.mint(&samwise, &starting_deposit);
    stable_client.mint(&samwise, &starting_deposit);

    pool_client.submit(
        &whale,
        &whale,
        &whale,
        &vec![
            &fixture.env,
            Request {
                request_type: RequestType::SupplyCollateral as u32,
                address: xlm_client.address.clone(),
                amount: whale_deposit,
            },
            Request {
                request_type: RequestType::SupplyCollateral as u32,
                address: stable_client.address.clone(),
                amount: whale_deposit,
            },
            Request {
                request_type: RequestType::Borrow as u32,
                address: xlm_client.address.clone(),
                amount: whale_deposit / 2 + starting_deposit / 2,
            },
            Request {
                request_type: RequestType::Borrow as u32,
                address: stable_client.address.clone(),
                amount: whale_deposit / 2 + starting_deposit / 2,
            },
        ],
    );

    pool_client.submit(
        &samwise,
        &samwise,
        &samwise,
        &vec![
            &fixture.env,
            Request {
                request_type: RequestType::SupplyCollateral as u32,
                address: xlm_client.address.clone(),
                amount: starting_deposit,
            },
            Request {
                request_type: RequestType::SupplyCollateral as u32,
                address: stable_client.address.clone(),
                amount: starting_deposit,
            },
        ],
    );

    // load reserve data pre accrual
    let xlm_reserve_data_0 = pool_client.get_reserve(&xlm_client.address);
    let stable_reserve_data_0 = pool_client.get_reserve(&stable_client.address);

    /*
     * Cause a bunch of accruals to verify interest rates
     */
    let mut xlm_added = 0;
    let mut stable_added = 0;
    for day in 0..365 {
        fixture.jump_with_sequence(24 * 60 * 60);
        // supply_collateral by a borrower now loads the reserve price (Guardian L-02);
        // keep the mock oracle instance from archiving over the year-long loop
        fixture.env.as_contract(&fixture.oracle.address, || {
            fixture
                .env
                .storage()
                .instance()
                .extend_ttl(999_999, 9_999_999)
        });

        // supply from pool to cause b_rate update and maintain ~50% util rate
        // 100m tokens borrowed for each reserve @ a 10% borrow rate
        let approx_daily_interest = 160_0000000;
        xlm_added += approx_daily_interest;

        let mut reqeusts = vec![
            &fixture.env,
            Request {
                request_type: RequestType::SupplyCollateral as u32,
                address: xlm_client.address.clone(),
                amount: approx_daily_interest,
            },
        ];

        if day % 30 == 0 {
            stable_added += approx_daily_interest * 30;
            reqeusts.push_back(Request {
                request_type: RequestType::SupplyCollateral as u32,
                address: stable_client.address.clone(),
                amount: approx_daily_interest * 30,
            });
        }

        pool_client.submit(&whale, &whale, &whale, &reqeusts);
    }

    // Read-only reserve loading includes accrual through the final ledger.
    let xlm_reserve_data_1 = pool_client.get_reserve(&xlm_client.address);
    let stable_reserve_data_1 = pool_client.get_reserve(&stable_client.address);

    let d_rate_gain_daily = 1.10516;
    let d_rate_gain_monthly = 1.10471;

    let actual_d_rate_gain_xlm =
        xlm_reserve_data_1.data.d_rate as f64 / xlm_reserve_data_0.data.d_rate as f64;
    let actual_d_rate_gain_stable =
        stable_reserve_data_1.data.d_rate as f64 / stable_reserve_data_0.data.d_rate as f64;

    // assert expected IR wihtin 0.05%
    assert_approx_eq_abs(actual_d_rate_gain_xlm, d_rate_gain_daily, 0.0005);
    assert_approx_eq_abs(actual_d_rate_gain_stable, d_rate_gain_monthly, 0.0005);

    // Zero take: borrower interest becomes supplier claims, less stock rounding.
    // Each b_rate floor loses < b_supply/SCALAR_12 + 1 asset units;
    // each deposit's b-token floor loses < b_rate/SCALAR_12 + 1.
    // Final supply/rate bound this deposit-only, positive-interest book.
    for (before, after, deposited, accruals, deposits) in [
        (
            &xlm_reserve_data_0,
            &xlm_reserve_data_1,
            xlm_added,
            365,
            365,
        ),
        (
            &stable_reserve_data_0,
            &stable_reserve_data_1,
            stable_added,
            14,
            13,
        ),
    ] {
        let supplier_interest =
            after.total_supply(&fixture.env) - before.total_supply(&fixture.env) - deposited;
        let borrower_interest =
            after.total_liabilities(&fixture.env) - before.total_liabilities(&fixture.env);
        let dust = borrower_interest - supplier_interest;
        let rounding_bound = accruals * (after.data.b_supply / SCALAR_12 + 1)
            + deposits * (after.data.b_rate / SCALAR_12 + 1);
        assert!(
            dust >= 0 && dust <= rounding_bound,
            "unaccounted interest {dust} exceeds rounding bound {rounding_bound}"
        );
        assert_eq!(after.data.backstop_credit, 0);
    }
}
