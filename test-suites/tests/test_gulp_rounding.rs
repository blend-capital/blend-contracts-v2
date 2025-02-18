#![cfg(test)]
use std::i128;

use pool::{Request, RequestType};
use soroban_sdk::{testutils::Address as AddressTestTrait, vec, Address};
use test_suites::{
    create_fixture_with_data,
    test_fixture::{TokenIndex, SCALAR_7},
};

#[test]
fn test_gulp_rounding() {
    let fixture = create_fixture_with_data(false);
    let pool_fixture = &fixture.pools[0];

    let stable = &fixture.tokens[TokenIndex::STABLE];

    // under collateral cap for stable
    let min_deposit = SCALAR_7;

    // Create a user
    let samwise = Address::generate(&fixture.env);
    stable.mint(&samwise, &(min_deposit * 100_000));

    // deposit tokens
    let deposit_requests = vec![
        &fixture.env,
        Request {
            request_type: RequestType::SupplyCollateral as u32,
            address: stable.address.clone(),
            amount: min_deposit,
        },
    ];
    pool_fixture
        .pool
        .submit(&samwise, &samwise, &samwise, &deposit_requests);

    // send tokens to pool
    stable.transfer(
        &samwise,
        &pool_fixture.pool.address,
        &(min_deposit * 99_999),
    );

    // call gulp
    pool_fixture.pool.gulp(&stable.address);

    // Merry deposits
    let merry = Address::generate(&fixture.env);
    stable.mint(&merry, &(min_deposit * 10_000));

    // deposit tokens
    let deposit_requests = vec![
        &fixture.env,
        Request {
            request_type: RequestType::SupplyCollateral as u32,
            address: stable.address.clone(),
            amount: min_deposit * 10_000,
        },
    ];
    pool_fixture
        .pool
        .submit(&merry, &merry, &merry, &deposit_requests);

    // validate the funds can still be withdrawn
    let withdraw_requests = vec![
        &fixture.env,
        Request {
            request_type: RequestType::WithdrawCollateral as u32,
            address: stable.address.clone(),
            amount: i128::MAX,
        },
    ];
    pool_fixture
        .pool
        .submit(&samwise, &samwise, &samwise, &withdraw_requests);
    pool_fixture
        .pool
        .submit(&merry, &merry, &merry, &withdraw_requests);
    // assert that sam did not make money
    assert!(stable.balance(&samwise) <= min_deposit * 100_000);
    // assert that merry did not lose money
    assert!(stable.balance(&merry) >= min_deposit * 10_000 - 50); //50 for rounding
}
