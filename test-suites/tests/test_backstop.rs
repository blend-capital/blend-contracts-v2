#![cfg(test)]

use backstop::{BackstopClient, BackstopContract};
use soroban_fixed_point_math::FixedPoint;
use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Events},
    vec, Address, Env, IntoVal, Symbol, Val, Vec,
};
use test_suites::{
    assertions::assert_approx_eq_abs,
    create_fixture_with_data,
    test_fixture::{TokenIndex, SCALAR_7},
};

/// Test user exposed functions on the backstop for basic functionality, auth, and events.
/// Does not test internal state management of the backstop, only external effects.
#[test]
fn test_backstop() {
    let fixture = create_fixture_with_data(false);
    let frodo = fixture.users.get(0).unwrap();

    let pool = &fixture.pools[0].pool;
    let bstop_token = &fixture.lp;
    let sam = Address::generate(&fixture.env);

    // Verify constructor set the backstop token
    assert_eq!(
        fixture.backstop.backstop_token(),
        bstop_token.address.clone()
    );

    // Mint some backstop tokens
    // assumes Sam makes up 20% of the backstop after depositing (50k / 0.8 * 0.2 = 12.5k)
    //  -> mint 12.5k LP tokens to sam
    fixture.tokens[TokenIndex::BLND].mint(&sam, &(125_001_000_0000_0000_000_000 * SCALAR_7)); // 10 BLND per LP token
    fixture.tokens[TokenIndex::BLND].approve(&sam, &bstop_token.address, &i128::MAX, &99999);
    fixture.tokens[TokenIndex::USDC].mint(&sam, &(3_126_000_0000_0000_000_000 * SCALAR_7)); // 0.25 USDC per LP token
    fixture.tokens[TokenIndex::USDC].approve(&sam, &bstop_token.address, &i128::MAX, &99999);
    bstop_token.join_pool(
        &(12_500 * SCALAR_7),
        &vec![
            &fixture.env,
            125_001_000_0000_0000_000 * SCALAR_7,
            3_126_000_0000_0000_000 * SCALAR_7,
        ],
        &sam,
    );

    //  -> mint Frodo additional backstop tokens (5k) for donation later
    fixture.tokens[TokenIndex::BLND].mint(&frodo, &(50_001 * SCALAR_7)); // 10 BLND per LP token
    fixture.tokens[TokenIndex::BLND].approve(&frodo, &bstop_token.address, &i128::MAX, &99999);
    fixture.tokens[TokenIndex::USDC].mint(&frodo, &(1_251 * SCALAR_7)); // 0.25 USDC per LP token
    fixture.tokens[TokenIndex::USDC].approve(&frodo, &bstop_token.address, &i128::MAX, &99999);
    bstop_token.join_pool(
        &(5_000 * SCALAR_7),
        &vec![&fixture.env, 50_001 * SCALAR_7, 1_251 * SCALAR_7],
        &frodo,
    );

    let mut frodo_bstop_token_balance = bstop_token.balance(&frodo);
    let mut bstop_bstop_token_balance = bstop_token.balance(&fixture.backstop.address);
    let mut sam_bstop_token_balance = bstop_token.balance(&sam);
    assert_eq!(sam_bstop_token_balance, 12_500 * SCALAR_7);

    // Sam deposits 12.5k backstop tokens
    let amount = 12_500 * SCALAR_7;
    let result = fixture.backstop.deposit(&sam, &pool.address, &amount);
    sam_bstop_token_balance -= amount;
    bstop_bstop_token_balance += amount;
    assert_eq!(
        fixture.env.auths()[0],
        (
            sam.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "deposit"),
                    vec![
                        &fixture.env,
                        sam.to_val(),
                        pool.address.to_val(),
                        amount.into_val(&fixture.env)
                    ]
                )),
                sub_invocations: std::vec![AuthorizedInvocation {
                    function: AuthorizedFunction::Contract((
                        bstop_token.address.clone(),
                        Symbol::new(&fixture.env, "transfer"),
                        vec![
                            &fixture.env,
                            sam.to_val(),
                            fixture.backstop.address.to_val(),
                            amount.into_val(&fixture.env)
                        ]
                    )),
                    sub_invocations: std::vec![]
                }]
            }
        )
    );
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    let event_body: Vec<Val> = vec![
        &fixture.env,
        amount.into_val(&fixture.env),
        result.into_val(&fixture.env),
    ];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (
                    Symbol::new(&fixture.env, "deposit"),
                    pool.address.clone(),
                    sam.clone()
                )
                    .into_val(&fixture.env),
                event_body.into_val(&fixture.env)
            )
        ]
    );
    assert_eq!(result, amount);
    assert_eq!(bstop_token.balance(&sam), sam_bstop_token_balance);
    assert_eq!(
        bstop_token.balance(&fixture.backstop.address),
        bstop_bstop_token_balance
    );

    // Simulate the pool backstop making money and progress 6d23h (6d23hr total emissions for sam)
    // @dev: setup jumps 1 hour and 1 minute
    fixture.jump(60 * 60 * 24 * 7 - 60 * 60);
    // Start the next emission cycle
    fixture.emitter.distribute();
    fixture.backstop.distribute();
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (Symbol::new(&fixture.env, "distribute"),).into_val(&fixture.env),
                ((60 * 60 * 24 * 7 + 60) * SCALAR_7).into_val(&fixture.env),
            )
        ]
    );
    pool.gulp_emissions();
    let amount = 2_000 * SCALAR_7;
    fixture.lp.approve(
        &frodo,
        &fixture.backstop.address,
        &amount,
        &fixture.env.ledger().sequence(),
    );
    fixture.backstop.donate(&frodo, &pool.address, &amount);
    frodo_bstop_token_balance -= amount;
    bstop_bstop_token_balance += amount;
    assert_eq!(
        fixture.env.auths()[0],
        (
            frodo.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "donate"),
                    vec![
                        &fixture.env,
                        frodo.to_val(),
                        pool.address.to_val(),
                        amount.into_val(&fixture.env)
                    ]
                )),
                sub_invocations: std::vec![]
            }
        )
    );
    assert_eq!(
        fixture.env.auths()[1],
        (
            pool.address.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "donate"),
                    vec![
                        &fixture.env,
                        frodo.to_val(),
                        pool.address.to_val(),
                        amount.into_val(&fixture.env)
                    ]
                )),
                sub_invocations: std::vec![]
            }
        )
    );
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (
                    Symbol::new(&fixture.env, "donate"),
                    pool.address.clone(),
                    frodo.clone()
                )
                    .into_val(&fixture.env),
                amount.into_val(&fixture.env)
            )
        ]
    );
    assert_eq!(bstop_token.balance(&frodo), frodo_bstop_token_balance);
    assert_eq!(
        bstop_token.balance(&fixture.backstop.address),
        bstop_bstop_token_balance
    );

    assert_eq!(fixture.env.auths().len(), 0);

    // Sam queues 100% of position for withdrawal
    let amount = 12_500 * SCALAR_7; // shares
    let result = fixture
        .backstop
        .queue_withdrawal(&sam, &pool.address, &amount);
    assert_eq!(
        fixture.env.auths()[0],
        (
            sam.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "queue_withdrawal"),
                    vec![
                        &fixture.env,
                        sam.to_val(),
                        pool.address.to_val(),
                        amount.into_val(&fixture.env)
                    ]
                )),
                sub_invocations: std::vec![]
            }
        )
    );
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    let event_body: Vec<Val> = vec![
        &fixture.env,
        amount.into_val(&fixture.env),
        result.exp.into_val(&fixture.env),
    ];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (
                    Symbol::new(&fixture.env, "queue_withdrawal"),
                    pool.address.clone(),
                    sam.clone()
                )
                    .into_val(&fixture.env),
                event_body.into_val(&fixture.env)
            )
        ]
    );
    assert_eq!(result.amount, amount);
    assert_eq!(
        result.exp,
        fixture.env.ledger().timestamp() + 21 * 24 * 60 * 60
    );
    assert_eq!(bstop_token.balance(&sam), sam_bstop_token_balance);
    assert_eq!(
        bstop_token.balance(&fixture.backstop.address),
        bstop_bstop_token_balance
    );

    // Start the next emission cycle and jump 7 days (13d23hr total emissions for sam)
    fixture.jump(60 * 60 * 24 * 7);
    fixture.emitter.distribute();
    fixture.backstop.distribute();
    pool.gulp_emissions();

    // Sam dequeues half of the withdrawal
    let amount = 6_250 * SCALAR_7; // shares
    fixture
        .backstop
        .dequeue_withdrawal(&sam, &pool.address, &amount);
    assert_eq!(
        fixture.env.auths()[0],
        (
            sam.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "dequeue_withdrawal"),
                    vec![
                        &fixture.env,
                        sam.to_val(),
                        pool.address.to_val(),
                        amount.into_val(&fixture.env)
                    ]
                )),
                sub_invocations: std::vec![]
            }
        )
    );
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (
                    Symbol::new(&fixture.env, "dequeue_withdrawal"),
                    pool.address.clone(),
                    sam.clone()
                )
                    .into_val(&fixture.env),
                amount.into_val(&fixture.env)
            )
        ]
    );
    assert_eq!(bstop_token.balance(&sam), sam_bstop_token_balance);
    assert_eq!(
        bstop_token.balance(&fixture.backstop.address),
        bstop_bstop_token_balance
    );

    // Start the next emission cycle and jump 7 days (20d23hr total emissions for sam)
    fixture.jump(60 * 60 * 24 * 7);
    fixture.emitter.distribute();
    fixture.backstop.distribute();
    pool.gulp_emissions();

    // Backstop loses money
    let amount = 1_000 * SCALAR_7;
    fixture.backstop.draw(&pool.address, &amount, &frodo);
    frodo_bstop_token_balance += amount;
    bstop_bstop_token_balance -= amount;
    assert_eq!(
        fixture.env.auths()[0],
        (
            pool.address.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "draw"),
                    vec![
                        &fixture.env,
                        pool.address.to_val(),
                        amount.into_val(&fixture.env),
                        frodo.to_val()
                    ]
                )),
                sub_invocations: std::vec![]
            }
        )
    );
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (Symbol::new(&fixture.env, "draw"), pool.address.clone()).into_val(&fixture.env),
                vec![&fixture.env, frodo.to_val(), amount.into_val(&fixture.env),]
                    .into_val(&fixture.env)
            )
        ]
    );
    assert_eq!(bstop_token.balance(&frodo), frodo_bstop_token_balance);
    assert_eq!(
        bstop_token.balance(&fixture.backstop.address),
        bstop_bstop_token_balance
    );

    // Jump to the end of the withdrawal period (27d23hr total emissions for sam)
    fixture.jump(60 * 60 * 24 * 16 + 1);
    // Sam withdraws the queue position
    let amount = 6_250 * SCALAR_7; // shares
    let result = fixture.backstop.withdraw(&sam, &pool.address, &amount);
    sam_bstop_token_balance += result; // sam caught 20% of 1k profit and is withdrawing half his position
    bstop_bstop_token_balance -= result;
    assert_eq!(
        fixture.env.auths()[0],
        (
            sam.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "withdraw"),
                    vec![
                        &fixture.env,
                        sam.to_val(),
                        pool.address.to_val(),
                        amount.into_val(&fixture.env),
                    ]
                )),
                sub_invocations: std::vec![]
            }
        )
    );
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    let event_body: Vec<Val> = vec![
        &fixture.env,
        amount.into_val(&fixture.env),
        result.into_val(&fixture.env),
    ];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (
                    Symbol::new(&fixture.env, "withdraw"),
                    pool.address.clone(),
                    sam.clone()
                )
                    .into_val(&fixture.env),
                event_body.into_val(&fixture.env)
            )
        ]
    );
    assert_eq!(result, amount + 100 * SCALAR_7); // sam due 20% of 1k profit. Captures half (100) since withdrawing half his position.
    assert_eq!(bstop_token.balance(&sam), sam_bstop_token_balance);
    assert_eq!(
        bstop_token.balance(&fixture.backstop.address),
        bstop_bstop_token_balance
    );

    // Sam claims emissions earned on the backstop deposit
    let bstop_blend_balance = &fixture.tokens[TokenIndex::BLND].balance(&fixture.backstop.address);
    let comet_blend_balance = &fixture.tokens[TokenIndex::BLND].balance(&fixture.lp.address);
    fixture
        .backstop
        .claim(&sam, &vec![&fixture.env, pool.address.clone()], &sam);
    assert_eq!(
        fixture.env.auths()[0],
        (
            sam.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.backstop.address.clone(),
                    Symbol::new(&fixture.env, "claim"),
                    vec![
                        &fixture.env,
                        sam.to_val(),
                        vec![&fixture.env, pool.address.clone()].to_val(),
                        sam.to_val(),
                    ]
                )),
                sub_invocations: std::vec![]
            }
        )
    );

    //6d23hr at full
    //7 days at none
    //7 at 6250 + (60 * 60 * 24 * 16 + 1)
    let emission_share_1 = 0_7000000.fixed_mul_floor(0_2000000, SCALAR_7).unwrap();
    let emission_share_2 = 0_7000000.fixed_mul_floor(0_1111111, SCALAR_7).unwrap();
    let emitted_blnd_1 = ((7 * 24 * 60 * 60 - 61 * 60) * SCALAR_7)
        .fixed_mul_floor(emission_share_1, SCALAR_7)
        .unwrap();
    let emitted_blnd_2 = ((14 * 24 * 60 * 60 + 1) * SCALAR_7 + 2096012)
        .fixed_mul_floor(emission_share_2, SCALAR_7)
        .unwrap();
    let event = vec![&fixture.env, fixture.env.events().all().last_unchecked()];
    assert_eq!(
        event,
        vec![
            &fixture.env,
            (
                fixture.backstop.address.clone(),
                (Symbol::new(&fixture.env, "claim"), sam.clone()).into_val(&fixture.env),
                (emitted_blnd_1 + emitted_blnd_2).into_val(&fixture.env),
            )
        ]
    );

    assert_approx_eq_abs(
        fixture.tokens[TokenIndex::BLND].balance(&fixture.lp.address),
        comet_blend_balance + emitted_blnd_1 + emitted_blnd_2,
        SCALAR_7,
    );
    assert_approx_eq_abs(
        fixture.tokens[TokenIndex::BLND].balance(&fixture.backstop.address),
        bstop_blend_balance - emitted_blnd_1 - emitted_blnd_2,
        SCALAR_7,
    );
}

#[test]
fn test_backstop_constructor() {
    let e = Env::default();

    let backstop_token = Address::generate(&e);
    let emitter = Address::generate(&e);
    let blnd_token = Address::generate(&e);
    let usdc_token = Address::generate(&e);
    let pool_factory = Address::generate(&e);
    let drop_list: Vec<(Address, i128)> = vec![
        &e,
        (Address::generate(&e), 10_000_000_0000000),
        (Address::generate(&e), 10_000_000_0000000),
        (Address::generate(&e), 10_000_000_0000000),
        (Address::generate(&e), 10_000_000_0000000),
    ];
    let contract_id = e.register(
        BackstopContract {},
        (
            backstop_token.clone(),
            emitter.clone(),
            blnd_token.clone(),
            usdc_token.clone(),
            pool_factory.clone(),
            drop_list.clone(),
        ),
    );

    e.as_contract(&contract_id, || {
        let contract_drop_list = e
            .storage()
            .persistent()
            .get::<Symbol, Vec<(Address, i128)>>(&Symbol::new(&e, "DropList"))
            .unwrap();
        assert_eq!(contract_drop_list, drop_list);

        let contract_emitter = e
            .storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(&e, "Emitter"))
            .unwrap();
        assert_eq!(contract_emitter, emitter);

        let contract_blnd_token = e
            .storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(&e, "BLNDTkn"))
            .unwrap();
        assert_eq!(contract_blnd_token, blnd_token);

        let contract_usdc_token = e
            .storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(&e, "USDCTkn"))
            .unwrap();
        assert_eq!(contract_usdc_token, usdc_token);

        let contract_pool_factory = e
            .storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(&e, "PoolFact"))
            .unwrap();
        assert_eq!(contract_pool_factory, pool_factory);
    });

    let backstop_client = BackstopClient::new(&e, &contract_id);
    assert_eq!(backstop_client.backstop_token(), backstop_token);
}

#[test]
#[should_panic(expected = "Error(Contract, #1000)")]
fn test_backstop_constructor_over_max() {
    let e = Env::default();

    let backstop_token = Address::generate(&e);
    let emitter = Address::generate(&e);
    let blnd_token = Address::generate(&e);
    let usdc_token = Address::generate(&e);
    let pool_factory = Address::generate(&e);
    let drop_list: Vec<(Address, i128)> = vec![
        &e,
        (Address::generate(&e), 10_000_000_0000000),
        (Address::generate(&e), 10_000_000_0000000),
        (Address::generate(&e), 10_000_000_0000000),
        (Address::generate(&e), 10_000_000_0000001),
    ];
    e.register(
        BackstopContract {},
        (
            backstop_token.clone(),
            emitter.clone(),
            blnd_token.clone(),
            usdc_token.clone(),
            pool_factory.clone(),
            drop_list.clone(),
        ),
    );
}
