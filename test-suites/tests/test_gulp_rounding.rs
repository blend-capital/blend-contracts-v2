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
    stable.mint(&samwise, &(i64::MAX as i128));

    // deposit tokens
    let deposit_requests = vec![
        &fixture.env,
        Request {
            request_type: RequestType::Supply as u32,
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
        &(i64::MAX as i128 - min_deposit),
    );

    // call gulp
    pool_fixture.pool.gulp(&stable.address);
    println!("{}", stable.balance(&pool_fixture.pool.address));
    println!("{}", stable.balance(&samwise));
    println!("================");

    // Merry deposits
    let merry = Address::generate(&fixture.env);
    stable.mint(&merry, &(min_deposit * 100_000));

    // deposit tokens
    let deposit_requests = vec![
        &fixture.env,
        Request {
            request_type: RequestType::Supply as u32,
            address: stable.address.clone(),
            amount: min_deposit * 100_000,
        },
    ];
    pool_fixture
        .pool
        .submit(&merry, &merry, &merry, &deposit_requests);

    // validate the funds can still be withdrawn
    let withdraw_requests = vec![
        &fixture.env,
        Request {
            request_type: RequestType::Withdraw as u32,
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
    println!("sam pre-balance: {}", i64::MAX as i128);
    println!("sam post-balance: {}", stable.balance(&samwise));
    assert!(stable.balance(&samwise) <= i64::MAX as i128);
    // assert that merry did not lose money
    println!("merry pre-balance: {}", min_deposit * 100_000 - 50);
    println!("merry post-balance: {}", stable.balance(&merry));
    println!(
        "pool balance: {}",
        stable.balance(&pool_fixture.pool.address)
    );
    assert!(stable.balance(&merry) >= min_deposit * 100_000 - 5000000000); //50 for rounding
    println!("================");
    // deposit tokens
    let deposit_requests = vec![
        &fixture.env,
        Request {
            request_type: RequestType::Supply as u32,
            address: stable.address.clone(),
            amount: min_deposit,
        },
    ];
    pool_fixture
        .pool
        .submit(&samwise, &samwise, &samwise, &deposit_requests);

    // call gulp
    pool_fixture.pool.gulp(&stable.address);
    pool_fixture
        .pool
        .submit(&samwise, &samwise, &samwise, &withdraw_requests);
    println!("sam post-balance: {}", stable.balance(&samwise));
    println!(
        "pool balance: {}",
        stable.balance(&pool_fixture.pool.address)
    );
}
