#![cfg(test)]
use pool::{FlashLoan, Request, RequestType };
use soroban_sdk::{vec, Vec};
use test_suites::{create_fixture_with_data, moderc3156::create_flashloan_receiver, test_fixture::{TokenIndex, SCALAR_7}};

#[test]
fn test_flashloan() {
    let fixture = create_fixture_with_data(false);
    let frodo = fixture.users.get(0).unwrap();
    let pool_fixture = &fixture.pools[0];
    let (receiver_address, receiver_client) = create_flashloan_receiver(&fixture.env);
    receiver_client.init(frodo);
    
    // reset frodo's health. 
    // TODO: there probably is a user in the fixture that doesn't require this due to low hf? haven't really looked into it.
    {
        let requests: Vec<Request> = vec![
        &fixture.env,
        Request {
            request_type: RequestType::Borrow as u32,
            address: fixture.tokens[TokenIndex::XLM].address.clone(),
            amount: 20_000 * SCALAR_7,
        },
        Request {
            request_type: RequestType::Borrow as u32,
            address: fixture.tokens[TokenIndex::STABLE].address.clone(),
            amount: 22 * SCALAR_7,
        },
        ];
        pool_fixture.pool.submit(&frodo, &frodo, &frodo, &requests);
    }

    // this request rebalances the flash loan borrow.
    // we need to account for the overcollateralization too, so it cannot be the same
    // exact amount borrowed. 
    let requests: Vec<Request> = vec![
        &fixture.env,
        Request {
            request_type: RequestType::SupplyCollateral as u32,
            address: fixture.tokens[TokenIndex::XLM].address.clone(),
            amount: 2_000 * SCALAR_7,
        },
        
    ];

    let xlm = &fixture.tokens[TokenIndex::XLM];
    let xlm_address = xlm.address.clone();

    // approval that will repay the flash loan. note that we can specify any amount that 
    // is >= the amount used to repay since it's just an allowance. Big allowances will probably 
    // be a standard for bots and flash loan operators as they gain more trust in the contracts.
    xlm.approve(frodo, &pool_fixture.pool.address, &(10_000 * SCALAR_7), &10000);
    
    pool_fixture.pool.flash_loan(&frodo, &FlashLoan { contract: receiver_address, asset: xlm_address, amount: 1_000 * SCALAR_7 }, &requests);
}
