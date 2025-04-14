use crate::{
    constants::SCALAR_7, dependencies::BackstopClient, errors::PoolError, pool::Pool, storage,
};
use cast::i128;
use sep_41_token::TokenClient;
use soroban_fixed_point_math::SorobanFixedPoint;
use soroban_sdk::{map, panic_with_error, Address, Env, Vec};

use super::{AuctionData, AuctionType};

pub fn create_interest_auction_data(
    e: &Env,
    user: &Address,
    bid: &Vec<Address>,
    lot: &Vec<Address>,
    percent: u32,
) -> AuctionData {
    let backstop = storage::get_backstop(e);
    if user != &backstop {
        panic_with_error!(e, PoolError::BadRequest);
    }
    if percent != 100 {
        panic_with_error!(e, PoolError::BadRequest);
    }
    if storage::has_auction(e, &(AuctionType::InterestAuction as u32), &backstop) {
        panic_with_error!(e, PoolError::AuctionInProgress);
    }

    let mut pool = Pool::load(e);
    // bid is required to have 1 entry, so require lot to have less than max_positions entries
    if pool.config.max_positions <= lot.len() {
        panic_with_error!(e, PoolError::MaxPositionsExceeded);
    }
    let oracle_scalar = 10i128.pow(pool.load_price_decimals(e));
    let mut auction_data = AuctionData {
        lot: map![e],
        bid: map![e],
        block: e.ledger().sequence() + 1,
    };

    // validate and create lot auction data
    let mut interest_value = 0; // expressed in the oracle's decimals
    for lot_asset in lot {
        // don't store updated reserve data back to ledger. This will occur on the the auction's fill.
        // `load_reserve` will panic if the reserve does not exist
        let reserve = pool.load_reserve(e, &lot_asset, false);
        if reserve.data.backstop_credit > 0 {
            let asset_to_base = pool.load_price(e, &reserve.asset);
            interest_value += i128(asset_to_base).fixed_mul_floor(
                e,
                &reserve.data.backstop_credit,
                &reserve.scalar,
            );
            auction_data
                .lot
                .set(reserve.asset, reserve.data.backstop_credit);
        }
    }

    if auction_data.lot.is_empty() {
        panic_with_error!(e, PoolError::InvalidLot);
    }

    // Ensure that the interest value is at least 200 USDC
    if interest_value < 200 * oracle_scalar {
        panic_with_error!(e, PoolError::InterestTooSmall);
    }

    // validate and create bid auction data
    let backstop_client = BackstopClient::new(e, &backstop);
    let backstop_token = backstop_client.backstop_token();
    if bid.len() != 1 || bid.get_unchecked(0) != backstop_token {
        panic_with_error!(e, PoolError::InvalidBid);
    }

    let pool_backstop_data = backstop_client.pool_data(&e.current_contract_address());
    // backstop tokens use 7 decimals
    let bid_amount = interest_value // oracle_scalar
        .fixed_mul_floor(e, &1_2000000, &oracle_scalar) // denom of oracle_scalar means result is SCALAR_7
        .fixed_div_floor(e, &pool_backstop_data.token_spot_price, &SCALAR_7); // token_spot_price is SCALAR_7
    auction_data.bid.set(backstop_token, bid_amount);

    auction_data
}

pub fn fill_interest_auction(
    e: &Env,
    pool: &mut Pool,
    auction_data: &AuctionData,
    filler: &Address,
) {
    // bid only contains the Backstop token
    let backstop = storage::get_backstop(e);
    if filler.clone() == backstop {
        panic_with_error!(e, PoolError::BadRequest);
    }
    let backstop_client = BackstopClient::new(&e, &backstop);
    let backstop_token: Address = backstop_client.backstop_token();
    let backstop_token_bid_amount = auction_data.bid.get(backstop_token).unwrap_or(0);
    if backstop_token_bid_amount > 0 {
        backstop_client.donate(
            &filler,
            &e.current_contract_address(),
            &backstop_token_bid_amount,
        );
    }

    // lot contains underlying tokens, but the backstop credit must be updated on the reserve
    for (res_asset_address, lot_amount) in auction_data.lot.iter() {
        let mut reserve = pool.load_reserve(e, &res_asset_address, true);
        reserve.data.backstop_credit -= lot_amount;
        pool.cache_reserve(reserve);
        TokenClient::new(e, &res_asset_address).transfer(
            &e.current_contract_address(),
            filler,
            &lot_amount,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        auctions::auction::AuctionType,
        storage::{self, PoolConfig},
        testutils::{self, create_comet_lp_pool, create_pool},
    };

    use super::*;
    use sep_40_oracle::testutils::Asset;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        vec, Address, Symbol,
    };

    #[test]
    #[should_panic(expected = "Error(Contract, #1212)")]
    fn test_create_interest_auction_already_in_progress() {
        let e = Env::default();
        e.mock_all_auths();
        let pool_address = create_pool(&e);
        let backstop_address = Address::generate(&e);

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 100,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let auction_data = AuctionData {
            bid: map![&e],
            lot: map![&e],
            block: 50,
        };
        e.as_contract(&pool_address, || {
            storage::set_backstop(&e, &backstop_address);
            storage::set_auction(
                &e,
                &(AuctionType::InterestAuction as u32),
                &backstop_address,
                &auction_data,
            );

            create_interest_auction_data(&e, &backstop_address, &vec![&e], &vec![&e], 100);
        });
    }

    #[test]
    #[should_panic]
    fn test_create_interest_auction_no_reserve() {
        let e = Env::default();
        e.mock_all_auths();
        let pool_address = create_pool(&e);
        let backstop_address = Address::generate(&e);

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 100,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, Address::generate(&e)],
                &vec![&e, Address::generate(&e)],
                100,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1200)")]
    fn test_create_interest_auction_user_not_backstop() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let pool_address = create_pool(&e);
        let backstop_address = Address::generate(&e);
        let backstop_token_id = Address::generate(&e);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);
            storage::set_backstop(&e, &backstop_address);

            create_interest_auction_data(
                &e,
                &Address::generate(&e),
                &vec![&e, backstop_token_id.clone()],
                &vec![&e, backstop_token_id.clone()],
                100,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1200)")]
    fn test_create_interest_auction_percent_not_100() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let pool_address = create_pool(&e);
        let backstop_address = Address::generate(&e);
        let backstop_token_id = Address::generate(&e);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);
            storage::set_backstop(&e, &backstop_address);
            create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![&e, backstop_token_id.clone()],
                99,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1215)")]
    fn test_create_interest_auction_under_threshold() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let backstop_token = Address::generate(&e);
        let (backstop_address, _) = testutils::create_backstop(
            &e,
            &pool_address,
            &backstop_token,
            &usdc_id,
            &Address::generate(&e),
        );
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.b_rate = 1_100_000_000_000;
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 10_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        let (underlying_1, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.b_rate = 1_100_000_000_000;
        reserve_data_1.last_time = 12345;
        reserve_data_1.backstop_credit = 2_5000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );

        let (underlying_2, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_2, mut reserve_data_2) = testutils::default_reserve_meta();
        reserve_data_2.b_rate = 1_100_000_000_000;
        reserve_data_2.last_time = 12345;
        reserve_config_2.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_2,
            &reserve_config_2,
            &reserve_data_2,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(underlying_1.clone()),
                Asset::Stellar(underlying_2.clone()),
                Asset::Stellar(usdc_id.clone()),
            ],
            &7,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_0000000, 4_0000000, 100_0000000, 1_0000000]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token.clone()],
                &vec![
                    &e,
                    underlying_0.clone(),
                    underlying_1.clone(),
                    underlying_2.clone(),
                ],
                100,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1221)")]
    fn test_create_interest_auction_invalid_bid() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 200_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(usdc_id.clone()),
            ],
            &7,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_0000000, 4_0000000]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, underlying_0.clone()],
                &vec![&e, underlying_0.clone()],
                100,
            );
        });
    }

    #[test]
    #[should_panic]
    fn test_create_interest_auction_invalid_lot() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 200_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(usdc_id.clone()),
            ],
            &7,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_0000000, 4_0000000]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![&e, backstop_token_id.clone()],
                100,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1222)")]
    fn test_create_interest_auction_invalid_lot_empty() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 200_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(usdc_id.clone()),
            ],
            &7,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_0000000, 4_0000000]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![&e],
                100,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1208)")]
    fn test_create_interest_auction_checks_max_positions() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 100_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        let (underlying_1, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.last_time = 12345;
        reserve_data_1.backstop_credit = 25_0000000;
        reserve_data_1.b_supply = 250_0000000;
        reserve_data_1.d_supply = 187_5000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );

        let (underlying_2, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_2, mut reserve_data_2) = testutils::default_reserve_meta();
        reserve_data_2.last_time = 12345;
        reserve_data_1.backstop_credit = 1000;
        reserve_config_2.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_2,
            &reserve_config_2,
            &reserve_data_2,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(underlying_1.clone()),
                Asset::Stellar(underlying_2.clone()),
                Asset::Stellar(usdc_id.clone()),
            ],
            &7,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_0000000, 4_0000000, 100_0000000, 1_0000000]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 3,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![
                    &e,
                    underlying_0.clone(),
                    underlying_1.clone(),
                    underlying_2.clone(),
                ],
                100,
            );
        });
    }

    #[test]
    fn test_create_interest_auction() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 100_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        let (underlying_1, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.last_time = 12345;
        reserve_data_1.backstop_credit = 25_0000000;
        reserve_data_1.b_supply = 250_0000000;
        reserve_data_1.d_supply = 187_5000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );

        let (underlying_2, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_2, mut reserve_data_2) = testutils::default_reserve_meta();
        reserve_data_2.last_time = 12345;
        reserve_config_2.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_2,
            &reserve_config_2,
            &reserve_data_2,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(underlying_1.clone()),
                Asset::Stellar(underlying_2),
                Asset::Stellar(usdc_id.clone()),
            ],
            &7,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_0000000, 4_0000000, 100_0000000, 1_0000000]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            let result = create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![&e, underlying_0.clone(), underlying_1.clone()],
                100,
            );
            assert_eq!(result.block, 51);
            assert_eq!(result.bid.get_unchecked(backstop_token_id), 288_0000000);
            assert_eq!(result.bid.len(), 1);
            assert_eq!(result.lot.get_unchecked(underlying_0), 100_0000000);
            assert_eq!(result.lot.get_unchecked(underlying_1), 25_0000000);
            assert_eq!(result.lot.len(), 2);
        });
    }

    #[test]
    fn test_create_interest_auction_14_decimal_oracle() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 100_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        let (underlying_1, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.last_time = 12345;
        reserve_data_1.backstop_credit = 25_0000000;
        reserve_data_1.b_supply = 250_0000000;
        reserve_data_1.d_supply = 187_5000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );

        let (underlying_2, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_2, mut reserve_data_2) = testutils::default_reserve_meta();
        reserve_data_2.last_time = 12345;
        reserve_config_2.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_2,
            &reserve_config_2,
            &reserve_data_2,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(underlying_1.clone()),
                Asset::Stellar(underlying_2),
                Asset::Stellar(usdc_id.clone()),
            ],
            &14,
            &300,
        );
        oracle_client.set_price_stable(&vec![
            &e,
            2_0000000_0000000,
            4_0000000_0000000,
            100_0000000_0000000,
            1_0000000_0000000,
        ]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            let result = create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![&e, underlying_0.clone(), underlying_1.clone()],
                100,
            );
            assert_eq!(result.block, 51);
            assert_eq!(result.bid.get_unchecked(backstop_token_id), 288_0000000);
            assert_eq!(result.bid.len(), 1);
            assert_eq!(result.lot.get_unchecked(underlying_0), 100_0000000);
            assert_eq!(result.lot.get_unchecked(underlying_1), 25_0000000);
            assert_eq!(result.lot.len(), 2);
        });
    }

    #[test]
    fn test_create_interest_auction_2_decimal_oracle() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 50,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));
        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 100_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        let (underlying_1, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.last_time = 12345;
        reserve_data_1.backstop_credit = 25_0000000;
        reserve_data_1.b_supply = 250_0000000;
        reserve_data_1.d_supply = 187_5000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );

        let (underlying_2, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_2, mut reserve_data_2) = testutils::default_reserve_meta();
        reserve_data_2.last_time = 12345;
        reserve_config_2.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_2,
            &reserve_config_2,
            &reserve_data_2,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(underlying_1.clone()),
                Asset::Stellar(underlying_2),
                Asset::Stellar(usdc_id.clone()),
            ],
            &2,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_00, 4_00, 100_00, 1_00]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            let result = create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![&e, underlying_0.clone(), underlying_1.clone()],
                100,
            );
            assert_eq!(result.block, 51);
            assert_eq!(result.bid.get_unchecked(backstop_token_id), 288_0000000);
            assert_eq!(result.bid.len(), 1);
            assert_eq!(result.lot.get_unchecked(underlying_0), 100_0000000);
            assert_eq!(result.lot.get_unchecked(underlying_1), 25_0000000);
            assert_eq!(result.lot.len(), 2);
        });
    }

    #[test]
    fn test_create_interest_auction_applies_interest() {
        let e = Env::default();
        e.mock_all_auths();
        e.cost_estimate().budget().reset_unlimited(); // setup exhausts budget

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 150,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);

        let pool_address = create_pool(&e);
        let (usdc_id, _) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, _) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, _) = create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));

        let (oracle_id, oracle_client) = testutils::create_mock_oracle(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 11845;
        reserve_data_0.backstop_credit = 100_0000000;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );

        let (underlying_1, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.last_time = 11845;
        reserve_data_1.backstop_credit = 25_0000000;
        reserve_data_1.b_supply = 250_0000000;
        reserve_data_1.d_supply = 187_5000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );

        let (underlying_2, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_2, mut reserve_data_2) = testutils::default_reserve_meta();
        reserve_data_2.last_time = 11845;
        reserve_config_2.index = 2;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_2,
            &reserve_config_2,
            &reserve_data_2,
        );

        oracle_client.set_data(
            &bombadil,
            &Asset::Other(Symbol::new(&e, "USD")),
            &vec![
                &e,
                Asset::Stellar(underlying_0.clone()),
                Asset::Stellar(underlying_1.clone()),
                Asset::Stellar(underlying_2.clone()),
                Asset::Stellar(usdc_id.clone()),
            ],
            &7,
            &300,
        );
        oracle_client.set_price_stable(&vec![&e, 2_0000000, 4_0000000, 100_0000000, 1_0000000]);

        let pool_config = PoolConfig {
            oracle: oracle_id,
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        e.as_contract(&pool_address, || {
            storage::set_pool_config(&e, &pool_config);

            let result = create_interest_auction_data(
                &e,
                &backstop_address,
                &vec![&e, backstop_token_id.clone()],
                &vec![
                    &e,
                    underlying_0.clone(),
                    underlying_1.clone(),
                    underlying_2.clone(),
                ],
                100,
            );
            assert_eq!(result.block, 151);
            assert_eq!(result.bid.get_unchecked(backstop_token_id), 288_0008868);
            assert_eq!(result.bid.len(), 1);
            assert_eq!(result.lot.get_unchecked(underlying_0), 100_0000713);
            assert_eq!(result.lot.get_unchecked(underlying_1), 25_0000178);
            assert_eq!(result.lot.get_unchecked(underlying_2), 71);
            assert_eq!(result.lot.len(), 3);
        });
    }

    #[test]
    fn test_fill_interest_auction() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();
        e.cost_estimate().budget().reset_unlimited();

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 301,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let pool_address = create_pool(&e);

        let (usdc_id, usdc_client) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, blnd_client) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, backstop_token_client) =
            create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        blnd_client.mint(&samwise, &10_000_0000000);
        usdc_client.mint(&samwise, &250_0000000);
        let exp_ledger = e.ledger().sequence() + 100;
        blnd_client.approve(&bombadil, &backstop_token_id, &2_000_0000000, &exp_ledger);
        usdc_client.approve(&bombadil, &backstop_token_id, &2_000_0000000, &exp_ledger);
        backstop_token_client.join_pool(
            &(100 * SCALAR_7),
            &vec![&e, 10_000_0000000, 250_0000000],
            &samwise,
        );
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));

        let (underlying_0, underlying_0_client) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.b_rate = 1_100_000_000_000;
        reserve_data_0.b_supply = 200_000_0000000;
        reserve_data_0.d_supply = 100_000_0000000;
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 100_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );
        underlying_0_client.mint(&pool_address, &1_000_0000000);

        let (underlying_1, underlying_1_client) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.b_rate = 1_100_000_000_000;
        reserve_data_0.b_supply = 10_000_0000000;
        reserve_data_0.b_supply = 7_000_0000000;
        reserve_data_1.last_time = 12345;
        reserve_data_1.backstop_credit = 30_0000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );
        underlying_1_client.mint(&pool_address, &1_000_0000000);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        let mut auction_data = AuctionData {
            bid: map![&e, (backstop_token_id.clone(), 75_0000000)],
            lot: map![
                &e,
                (underlying_0.clone(), 100_0000000),
                (underlying_1.clone(), 25_0000000)
            ],
            block: 51,
        };

        backstop_token_client.approve(
            &samwise,
            &backstop_address,
            &75_0000000,
            &e.ledger().sequence(),
        );
        e.as_contract(&pool_address, || {
            e.mock_all_auths_allowing_non_root_auth();
            storage::set_auction(
                &e,
                &(AuctionType::InterestAuction as u32),
                &backstop_address,
                &auction_data,
            );
            storage::set_pool_config(&e, &pool_config);
            storage::set_backstop(&e, &backstop_address);
            let mut pool = Pool::load(&e);
            let backstop_token_balance_pre_fill = backstop_token_client.balance(&backstop_address);
            fill_interest_auction(&e, &mut pool, &mut auction_data, &samwise);
            pool.store_cached_reserves(&e);

            assert_eq!(backstop_token_client.balance(&samwise), 25_0000000);
            assert_eq!(
                backstop_token_client.balance(&backstop_address),
                backstop_token_balance_pre_fill + 75_0000000
            );
            assert_eq!(underlying_0_client.balance(&samwise), 100_0000000);
            assert_eq!(underlying_1_client.balance(&samwise), 25_0000000);
            // verify only filled backstop credits get deducted from total
            let reserve_0_data = storage::get_res_data(&e, &underlying_0);
            assert_eq!(reserve_0_data.backstop_credit, 0);
            let reserve_1_data = storage::get_res_data(&e, &underlying_1);
            assert_eq!(reserve_1_data.backstop_credit, 5_0000000);
        });
    }

    #[test]
    fn test_fill_interest_auction_empty_bid() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();
        e.cost_estimate().budget().reset_unlimited();

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 301,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let pool_address = create_pool(&e);

        let (usdc_id, usdc_client) = testutils::create_token_contract(&e, &bombadil);
        let (blnd_id, blnd_client) = testutils::create_blnd_token(&e, &pool_address, &bombadil);

        let (backstop_token_id, backstop_token_client) =
            create_comet_lp_pool(&e, &bombadil, &blnd_id, &usdc_id);
        blnd_client.mint(&samwise, &10_000_0000000);
        usdc_client.mint(&samwise, &250_0000000);
        let exp_ledger = e.ledger().sequence() + 100;
        blnd_client.approve(&bombadil, &backstop_token_id, &2_000_0000000, &exp_ledger);
        usdc_client.approve(&bombadil, &backstop_token_id, &2_000_0000000, &exp_ledger);
        backstop_token_client.join_pool(
            &(100 * SCALAR_7),
            &vec![&e, 10_000_0000000, 250_0000000],
            &samwise,
        );
        let (backstop_address, backstop_client) =
            testutils::create_backstop(&e, &pool_address, &backstop_token_id, &usdc_id, &blnd_id);
        backstop_client.deposit(&bombadil, &pool_address, &(50 * SCALAR_7));

        let (underlying_0, underlying_0_client) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.b_rate = 1_100_000_000_000;
        reserve_data_0.b_supply = 200_000_0000000;
        reserve_data_0.d_supply = 100_000_0000000;
        reserve_data_0.last_time = 12345;
        reserve_data_0.backstop_credit = 100_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );
        underlying_0_client.mint(&pool_address, &1_000_0000000);

        let (underlying_1, underlying_1_client) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.b_rate = 1_100_000_000_000;
        reserve_data_0.b_supply = 10_000_0000000;
        reserve_data_0.b_supply = 7_000_0000000;
        reserve_data_1.last_time = 12345;
        reserve_data_1.backstop_credit = 30_0000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );
        underlying_1_client.mint(&pool_address, &1_000_0000000);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        let mut auction_data = AuctionData {
            bid: map![&e],
            lot: map![
                &e,
                (underlying_0.clone(), 100_0000000),
                (underlying_1.clone(), 25_0000000)
            ],
            block: 51,
        };
        e.as_contract(&pool_address, || {
            e.mock_all_auths_allowing_non_root_auth();
            storage::set_auction(
                &e,
                &(AuctionType::InterestAuction as u32),
                &backstop_address,
                &auction_data,
            );
            storage::set_pool_config(&e, &pool_config);
            storage::set_backstop(&e, &backstop_address);
            let mut pool = Pool::load(&e);
            let backstop_token_balance_pre_fill = backstop_token_client.balance(&backstop_address);
            fill_interest_auction(&e, &mut pool, &mut auction_data, &samwise);
            pool.store_cached_reserves(&e);

            assert_eq!(backstop_token_client.balance(&samwise), 100 * SCALAR_7);
            assert_eq!(
                backstop_token_client.balance(&backstop_address),
                backstop_token_balance_pre_fill
            );
            assert_eq!(underlying_0_client.balance(&samwise), 100_0000000);
            assert_eq!(underlying_1_client.balance(&samwise), 25_0000000);
            // verify only filled backstop credits get deducted from total
            let reserve_0_data = storage::get_res_data(&e, &underlying_0);
            assert_eq!(reserve_0_data.backstop_credit, 0);
            let reserve_1_data = storage::get_res_data(&e, &underlying_1);
            assert_eq!(reserve_1_data.backstop_credit, 5_0000000);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1200)")]
    fn test_fill_interest_auction_with_backstop() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();
        e.cost_estimate().budget().reset_unlimited();

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 301,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let pool_address = create_pool(&e);

        let (usdc_id, usdc_client) = testutils::create_token_contract(&e, &bombadil);
        let (backstop_address, _) = testutils::create_backstop(
            &e,
            &pool_address,
            &Address::generate(&e),
            &usdc_id,
            &Address::generate(&e),
        );

        let (underlying_0, underlying_0_client) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, reserve_data_0) = testutils::default_reserve_meta();
        reserve_config_0.index = 0;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_0,
            &reserve_config_0,
            &reserve_data_0,
        );
        underlying_0_client.mint(&pool_address, &1_000_0000000);

        let (underlying_1, underlying_1_client) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, reserve_data_1) = testutils::default_reserve_meta();
        reserve_config_1.index = 1;
        testutils::create_reserve(
            &e,
            &pool_address,
            &underlying_1,
            &reserve_config_1,
            &reserve_data_1,
        );
        underlying_1_client.mint(&pool_address, &1_000_0000000);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 4,
        };
        let mut auction_data = AuctionData {
            bid: map![&e, (usdc_id.clone(), 95_0000000)],
            lot: map![
                &e,
                (underlying_0.clone(), 100_0000000),
                (underlying_1.clone(), 25_0000000)
            ],
            block: 51,
        };
        usdc_client.mint(&samwise, &100_0000000);
        e.as_contract(&pool_address, || {
            e.mock_all_auths_allowing_non_root_auth();
            storage::set_auction(
                &e,
                &(AuctionType::InterestAuction as u32),
                &backstop_address,
                &auction_data,
            );
            storage::set_pool_config(&e, &pool_config);
            storage::set_backstop(&e, &backstop_address);

            let mut pool = Pool::load(&e);
            fill_interest_auction(&e, &mut pool, &mut auction_data, &backstop_address);
        });
    }
}
