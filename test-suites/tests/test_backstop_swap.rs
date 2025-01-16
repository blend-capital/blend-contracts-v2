#![cfg(test)]

use backstop::BackstopClient;
use blend_contract_sdk::emitter;
use pool::{PoolClient, Request, RequestType, ReserveEmissionMetadata};
use pool_factory::{PoolFactoryClient, PoolInitMeta};
use sep_40_oracle::testutils::Asset;
use sep_41_token::testutils::MockTokenClient;
use soroban_fixed_point_math::FixedPoint;
use soroban_sdk::{
    testutils::{Address as _, BytesN as _, Ledger},
    vec,
    xdr::Error,
    Address, BytesN, Env, String, Symbol, Val, Vec,
};
use test_suites::{
    assertions::assert_approx_eq_rel,
    backstop::create_backstop,
    liquidity_pool::LPClient,
    oracle::create_mock_oracle,
    pool::{default_reserve_metadata, POOL_WASM},
    pool_factory::create_pool_factory,
    snapshot::{self, XLM_WHALE},
    test_fixture::SCALAR_7,
};

#[test]
fn test_v1_to_v2_backstop_swap() {
    let env = snapshot::env_from_snapshot();
    env.mock_all_auths();

    let frodo = Address::generate(&env);
    let samwise = Address::generate(&env);
    let merry = Address::generate(&env);

    // contracts shared between v1 and v2
    let blnd = Address::from_str(&env, snapshot::BLND_ID);
    let usdc = Address::from_str(&env, snapshot::USDC_ID);
    let backstop_token = Address::from_str(&env, snapshot::BLND_USDC_LP_ID);
    let emitter = Address::from_str(&env, snapshot::EMITTER_ID);
    let v1_backstop = Address::from_str(&env, snapshot::BACKSTOP_ID);
    let v1_pool = Address::from_str(&env, snapshot::V1_POOL_ID);

    let usdc_client = MockTokenClient::new(&env, &usdc);
    let backstop_token_client = LPClient::new(&env, &backstop_token);
    let emitter_client = emitter::Client::new(&env, &emitter);
    let v1_backstop_client = BackstopClient::new(&env, &v1_backstop);
    let v1_pool_client = PoolClient::new(&env, &v1_pool);

    // deploy v2 contracts
    let v2_backstop = Address::generate(&env);
    let v2_pool_factory = Address::generate(&env);

    let pool_hash = env.deployer().upload_contract_wasm(POOL_WASM);
    let pool_init_meta = PoolInitMeta {
        backstop: v2_backstop.clone(),
        pool_hash: pool_hash.clone(),
        blnd_id: blnd.clone(),
    };
    let v2_pool_factory_client = create_pool_factory(&env, &v2_pool_factory, true, pool_init_meta);

    let drop_list: Vec<(Address, i128)> = vec![&env, (frodo.clone(), 1_000_000 * 10i128.pow(7))];
    let v2_backstop_client = create_backstop(
        &env,
        &v2_backstop,
        true,
        &backstop_token,
        &emitter,
        &blnd,
        &usdc,
        &v2_pool_factory,
        &drop_list,
    );

    // Backstop_v1 balance of BLND_USDC_LP tokens
    let mut to_match_v1 = backstop_token_client.balance(&v1_backstop);

    // Mint Merry LP tokens to deposit into v1 backstop
    mint_lp_tokens(&env, &backstop_token_client, &merry, 10_000 * SCALAR_7);
    v1_backstop_client.deposit(&merry, &v1_pool, &(10_000 * SCALAR_7));
    to_match_v1 += 10_000 * SCALAR_7;

    // Mint Merry USDC to deposit into v1 pool
    usdc_client.mint(&merry, &10_000_0000000);
    let requests: Vec<Request> = vec![
        &env,
        Request {
            request_type: RequestType::SupplyCollateral as u32,
            address: usdc.clone(),
            amount: 10_000_0000000,
        },
    ];
    v1_pool_client.submit(&merry, &merry, &merry, &requests);

    // Mint LP tokens to frodo and samwise
    // -> mint frodo enough LP tokens to swap
    mint_lp_tokens(&env, &backstop_token_client, &frodo, to_match_v1);
    // -> mint samwise enough LP tokens to backstop a new pool on v2
    mint_lp_tokens(&env, &backstop_token_client, &samwise, 55_000 * SCALAR_7);

    // Create v2 pool
    let v2_pool_id = deploy_v2_pool(&env, &samwise, &v2_pool_factory_client, &v2_backstop_client);
    let v2_pool_client = PoolClient::new(&env, &v2_pool_id);
    // -> track deposit of 55k LP tokens into v2 backstop during deploy_v2_pool
    to_match_v1 -= 55_000 * SCALAR_7;

    // Test: Validate distribute fails on v2 without swap
    emitter_client.distribute();
    assert!(v2_backstop_client.try_distribute().is_err());
    assert!(v2_pool_client.try_gulp_emissions().is_err());

    // start backstop swap
    // -> in v1 merry earns about 200 LP tokens per week in emissions
    let approx_v1_new_lp_tokens = 200 * SCALAR_7 * 4;
    v2_backstop_client.deposit(
        &frodo,
        &v2_pool_id,
        &(to_match_v1 + approx_v1_new_lp_tokens),
    );
    emitter_client.queue_swap_backstop(&v2_backstop, &backstop_token);

    // Time: pass 7 days (7 days since swap)
    jump(&env, 17280 * 7);

    // Test: Validate v1 still getting emissions and v2 is not
    // -> claim existing emissions
    // -> seed balances as trustlines not included in snapshot
    v1_backstop_client.claim(&merry, &vec![&env, v1_pool.clone()], &merry);
    v1_pool_client.claim(&merry, &vec![&env, 3], &merry);
    assert_eq!(
        v2_backstop_client.claim(&samwise, &vec![&env, v2_pool_id.clone()], &samwise),
        0
    );
    assert_eq!(
        v2_pool_client.claim(&samwise, &vec![&env, 1, 3], &samwise),
        0
    );
    // -> distribute emissions
    emitter_client.distribute();
    //   -> this fucntion was renamed on v2, just invoke v1 method directly
    env.invoke_contract::<Val>(
        &v1_backstop,
        &Symbol::new(&env, "gulp_emissions"),
        vec![&env] as Vec<Val>,
    );
    v1_pool_client.gulp_emissions();
    // -> validate v2 still can't distribute
    assert!(v2_backstop_client.try_distribute().is_err());
    assert!(v2_pool_client.try_gulp_emissions().is_err());
    // Time: pass 7 days (14 days since swap)
    jump(&env, 17280 * 7);
    // -> validate v1 got emissions and v2 did not
    let v1_7_days_backstop = v1_backstop_client.claim(&merry, &vec![&env, v1_pool.clone()], &merry);
    assert!(v1_7_days_backstop > 0);
    let v1_7_days_pool = v1_pool_client.claim(&merry, &vec![&env, 3], &merry);
    assert!(v1_7_days_pool > 0);
    assert_eq!(
        v2_backstop_client.claim(&samwise, &vec![&env, v2_pool_id.clone()], &samwise),
        0
    );
    assert_eq!(
        v2_pool_client.claim(&samwise, &vec![&env, 1, 3], &samwise),
        0
    );

    // Test: Validate v1 gets all emissions up until swap,
    //       the swap is successful, and v2 starts getting emissions after swap
    // -> distribute emissions for v1
    emitter_client.distribute();
    env.invoke_contract::<Val>(
        &v1_backstop,
        &Symbol::new(&env, "gulp_emissions"),
        vec![&env] as Vec<Val>,
    );
    v1_pool_client.gulp_emissions();
    // Time: pass 7 days (21 days since swap)
    jump(&env, 17280 * 7);

    // -> distribute emissions for v1
    emitter_client.distribute();
    env.invoke_contract::<Val>(
        &v1_backstop,
        &Symbol::new(&env, "gulp_emissions"),
        vec![&env] as Vec<Val>,
    );
    v1_pool_client.gulp_emissions();
    // Time: pass 7 days (28 days since swap)
    jump(&env, 17280 * 7);
    // -> claim emissions
    v1_backstop_client.claim(&merry, &vec![&env, v1_pool.clone()], &merry);
    v1_pool_client.claim(&merry, &vec![&env, 3], &merry);

    // -> distribute emissions for v1
    emitter_client.distribute();
    env.invoke_contract::<Val>(
        &v1_backstop,
        &Symbol::new(&env, "gulp_emissions"),
        vec![&env] as Vec<Val>,
    );
    v1_pool_client.gulp_emissions();

    // Time: pass 3 days (31 days since swap)
    jump(&env, 17280 * 3 + 1);

    // -> do swap
    emitter_client.swap_backstop();
    assert_eq!(emitter_client.get_backstop(), v2_backstop);

    // -> v1 emitter distribute run automatically
    // -> run v2 distribute to set starting point for emissions
    v2_backstop_client.distribute();

    // Time: pass 4 days (4 days since swap)
    jump(&env, 17280 * 4);
    emitter_client.distribute();
    // -> claim v1 emissions
    v1_backstop_client.claim(&merry, &vec![&env, v1_pool.clone()], &merry);
    v1_pool_client.claim(&merry, &vec![&env, 3], &merry);
    // -> distribute v1 emissions (distributes 3 days of emissions over the next 7 days)
    env.invoke_contract::<Val>(
        &v1_backstop,
        &Symbol::new(&env, "gulp_emissions"),
        vec![&env] as Vec<Val>,
    );
    v1_pool_client.gulp_emissions();
    // -> distribute v2 emissions (distributes 4 days of emissions over the next 7 days)
    v2_backstop_client.distribute();
    v2_pool_client.gulp_emissions();

    // Time: pass 7 days (11 days since swap)
    jump(&env, 17280 * 7);

    // -> claim v2 emissions and validate approx. 4 days worth of emissions are claimed
    let tokens_emitted: i128 = 4 * 24 * 60 * 60 * SCALAR_7;
    // -> frodo gets virtually all backstop emissions (0.7 tokens per second)
    let v2_backstop_claim =
        v2_backstop_client.claim(&frodo, &vec![&env, v2_pool_id.clone()], &frodo);
    assert_approx_eq_rel(
        v2_backstop_claim,
        tokens_emitted.fixed_mul_floor(0_7000000, SCALAR_7).unwrap(),
        0_0500000,
    );
    // -> sawise gets all pool emissions as only user (0.3 tokens per second)
    let v2_pool_claim = v2_pool_client.claim(&samwise, &vec![&env, 1, 3], &samwise);
    assert_approx_eq_rel(
        v2_pool_claim,
        tokens_emitted.fixed_mul_floor(0_3000000, SCALAR_7).unwrap(),
        0_0500000,
    );

    // Time: pass 1 day (12 days since swap) to ensure emissions for pool 1 are over
    jump(&env, 17280);

    // -> claim v1 emissions and validate approx. 3 days worth of emissions are claimed.
    //    The wide bounds are due to multiple factors on the snapshot causing emissions to fluctuate
    //    between claim periods. Ultimately, this just validates that claim is working.
    let v1_backstop_claim = v1_backstop_client.claim(&merry, &vec![&env, v1_pool.clone()], &merry);
    assert_approx_eq_rel(
        v1_backstop_claim,
        v1_7_days_backstop
            .fixed_mul_floor(3_0000000, 7_0000000)
            .unwrap(),
        0_1000000,
    );
    let v1_pool_claim = v1_pool_client.claim(&merry, &vec![&env, 3], &merry);
    assert_approx_eq_rel(
        v1_pool_claim,
        v1_7_days_pool
            .fixed_mul_floor(3_0000000, 7_0000000)
            .unwrap(),
        0_1000000,
    );

    // Test: validate emissons stop to v1
    // -> distribute v1 emissions
    emitter_client.distribute();
    assert!(env
        .try_invoke_contract::<Val, Error>(
            &v1_backstop,
            &Symbol::new(&env, "gulp_emissions"),
            vec![&env] as Vec<Val>
        )
        .is_err());
    assert!(v1_pool_client.try_gulp_emissions().is_err());
    // -> claim v1 emissions and validate no emissions are claimed
    assert_eq!(
        v1_backstop_client.claim(&merry, &vec![&env, v1_pool.clone()], &merry),
        0
    );
    assert_eq!(v1_pool_client.claim(&merry, &vec![&env, 3], &merry), 0);
}

/// Jump the ledger by "blocks" blocks, each block is 5 seconds
fn jump(env: &Env, blocks: u32) {
    let seconds_passed: u64 = (blocks as u64) * 5;
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + blocks);
    env.ledger()
        .set_timestamp(env.ledger().timestamp() + seconds_passed);
}

/// Mint "amount" LP tokens to "user". This assumes the LP token is the starting
/// weights and no swaps have been made.
fn mint_lp_tokens(env: &Env, client: &LPClient, user: &Address, amount: i128) {
    let blnd = Address::from_str(&env, snapshot::BLND_ID);
    let usdc = Address::from_str(&env, snapshot::USDC_ID);
    let blnd_client = MockTokenClient::new(&env, &blnd);
    let usdc_client = MockTokenClient::new(&env, &usdc);
    // @ snapshot, LP shares are worth are ~0.09 USDC and ~4.401 BLND each
    let blnd_mint_amount = amount.fixed_mul_floor(4_40100000, SCALAR_7).unwrap();
    let usdc_mint_amount = amount.fixed_mul_floor(0_09000000, SCALAR_7).unwrap();
    blnd_client.mint(&user, &blnd_mint_amount);
    usdc_client.mint(&user, &usdc_mint_amount);
    client.join_pool(
        &amount,
        &vec![&env, blnd_mint_amount.clone(), usdc_mint_amount.clone()],
        &user,
    );
}

/// Mint XLM by transfering from a whale as explicit token minting is not supported
fn mint_xlm(env: &Env, user: &Address, amount: &i128) {
    let client = MockTokenClient::new(&env, &Address::from_str(&env, snapshot::XLM_ID));
    client.transfer(&Address::from_str(&env, XLM_WHALE), user, amount);
}

/// Deploy a basic v2 pool, enable borrowing, and have deployer setup positions
///
/// Creator must have 55k LP tokens to enable borrowing.
fn deploy_v2_pool(
    env: &Env,
    creator: &Address,
    pool_factory_client: &PoolFactoryClient,
    backstop_client: &BackstopClient,
) -> Address {
    let xlm = Address::from_str(&env, snapshot::XLM_ID);
    let usdc = Address::from_str(&env, snapshot::USDC_ID);

    // create an oracle for USDC and XLM pool
    let (oracle_id, mock_oracle_client) = create_mock_oracle(&env);
    mock_oracle_client.set_data(
        &creator,
        &Asset::Other(Symbol::new(&env, "USD")),
        &vec![
            &env,
            Asset::Stellar(xlm.clone()),
            Asset::Stellar(usdc.clone()),
        ],
        &7,
        &300,
    );
    mock_oracle_client.set_price_stable(&vec![
        &env, 0_4200000, // xlm
        1_0000000, // usdc
    ]);

    // create a pool
    let pool_id = pool_factory_client.deploy(
        &creator,
        &String::from_str(&env, "V2"),
        &BytesN::<32>::random(&env),
        &oracle_id,
        &0_1000000,
        &4,
    );
    let pool_client = PoolClient::new(&env, &pool_id);

    // setup reserves
    let mut xlm_config = default_reserve_metadata();
    xlm_config.c_factor = 0_750_0000;
    xlm_config.l_factor = 0_750_0000;
    xlm_config.util = 0_500_0000;
    xlm_config.max_util = 0_900_0000;
    pool_client.queue_set_reserve(&xlm, &xlm_config);
    pool_client.set_reserve(&xlm);

    let mut usdc_config = default_reserve_metadata();
    usdc_config.c_factor = 0_900_0000;
    usdc_config.l_factor = 0_950_0000;
    usdc_config.util = 0_800_0000;
    pool_client.queue_set_reserve(&usdc, &usdc_config);
    pool_client.set_reserve(&usdc);

    // split emissions equally between XLM and USDC supplying
    let reserve_emissions = vec![
        &env,
        ReserveEmissionMetadata {
            res_index: 0, // XLM
            res_type: 1,  // b_token
            share: 1_0000000,
        },
        ReserveEmissionMetadata {
            res_index: 1, // USDC
            res_type: 1,  // b_token
            share: 1_0000000,
        },
    ];
    pool_client.set_emissions_config(&reserve_emissions);

    // setup backstop and enable borrowing
    backstop_client.deposit(&creator, &pool_id, &(55_000 * SCALAR_7));
    backstop_client.update_tkn_val();
    backstop_client.add_reward(&pool_id, &None);
    pool_client.set_status(&3);
    pool_client.update_status();

    // creator adds liquidity to the pool
    let usdc_client = MockTokenClient::new(&env, &usdc);
    // xlm does not allow minting - take from a whale
    mint_xlm(&env, &creator, &10_000_0000000);
    usdc_client.mint(&creator, &5_000_0000000);

    let requests: Vec<Request> = vec![
        &env,
        Request {
            request_type: RequestType::SupplyCollateral as u32,
            address: xlm.clone(),
            amount: 10_000_0000000,
        },
        Request {
            request_type: RequestType::Borrow as u32,
            address: xlm.clone(),
            amount: 5_000_0000000,
        },
        Request {
            request_type: RequestType::SupplyCollateral as u32,
            address: usdc.clone(),
            amount: 5_000_0000000,
        },
        Request {
            request_type: RequestType::Borrow as u32,
            address: xlm.clone(),
            amount: 3_000_0000000,
        },
    ];
    pool_client.submit(&creator, &creator, &creator, &requests);

    pool_id
}
