use crate::{
    constants::{MAX_RESERVES, SCALAR_12, SCALAR_7, SECONDS_PER_WEEK},
    errors::PoolError,
    storage::{
        self, has_queued_reserve_set, PoolConfig, QueuedReserveInit, ReserveConfig, ReserveData,
    },
};
use soroban_sdk::{panic_with_error, Address, Env, String};

use super::{pool::Pool, Reserve};

/// Initialize the pool
///
/// Panics if the pool is already initialized or the arguments are invalid
#[allow(clippy::too_many_arguments)]
pub fn execute_initialize(
    e: &Env,
    admin: &Address,
    name: &String,
    oracle: &Address,
    bstop_rate: &u32,
    max_positions: &u32,
    min_collateral: &i128,
    backstop_address: &Address,
    blnd_id: &Address,
) {
    let pool_config = PoolConfig {
        oracle: oracle.clone(),
        min_collateral: *min_collateral,
        bstop_rate: *bstop_rate,
        status: 6,
        max_positions: *max_positions,
    };
    require_valid_pool_config(e, &pool_config);

    storage::set_admin(e, admin);
    storage::set_name(e, name);
    storage::set_backstop(e, backstop_address);
    storage::set_pool_config(e, &pool_config);
    storage::set_blnd_token(e, blnd_id);
}

/// Update the pool
pub fn execute_update_pool(
    e: &Env,
    backstop_take_rate: u32,
    max_positions: u32,
    min_collateral: i128,
) {
    let mut pool_config = storage::get_pool_config(e);
    let res_list = storage::get_res_list(e);
    if pool_config.bstop_rate != backstop_take_rate {
        for res in res_list {
            let reserve = Reserve::load(e, &pool_config, &res);
            reserve.store(e);
        }
    }
    pool_config.bstop_rate = backstop_take_rate;
    pool_config.max_positions = max_positions;
    pool_config.min_collateral = min_collateral;

    require_valid_pool_config(e, &pool_config);
    storage::set_pool_config(e, &pool_config);
}

/// Execute a queueing a reserve initialization for the pool
pub fn execute_queue_set_reserve(e: &Env, asset: &Address, metadata: &ReserveConfig) {
    if has_queued_reserve_set(e, asset) {
        panic_with_error!(&e, PoolError::BadRequest)
    }
    require_valid_reserve_metadata(e, metadata);

    // if the reserve config exists, ensure there are no invalid changes
    if storage::has_res(e, asset) {
        require_valid_reserve_metadata_changes(e, &storage::get_res_config(e, asset), metadata);
    }

    let mut unlock_time = e.ledger().timestamp();
    // require a timelock if pool status is not setup
    if storage::get_pool_config(e).status != 6 {
        unlock_time += SECONDS_PER_WEEK;
    }
    storage::set_queued_reserve_set(
        &e,
        &QueuedReserveInit {
            new_config: metadata.clone(),
            unlock_time,
        },
        &asset,
    );
}

/// Execute cancelling a queueing a reserve initialization for the pool
pub fn execute_cancel_queued_set_reserve(e: &Env, asset: &Address) {
    storage::del_queued_reserve_set(&e, &asset);
}

/// Execute a queued reserve initialization for the pool
pub fn execute_set_reserve(e: &Env, asset: &Address) -> u32 {
    let queued_init = storage::get_queued_reserve_set(e, asset);

    if queued_init.unlock_time > e.ledger().timestamp() {
        panic_with_error!(e, PoolError::InitNotUnlocked);
    }

    // remove queued reserve
    storage::del_queued_reserve_set(e, asset);

    // initialize reserve
    initialize_reserve(e, asset, &queued_init.new_config)
}

/// sets reserve data for the pool
fn initialize_reserve(e: &Env, asset: &Address, config: &ReserveConfig) -> u32 {
    let index: u32;
    // if reserve already exists, ensure index and scalar do not change
    if storage::has_res(e, asset) {
        // accrue and store reserve data to the ledger
        let mut pool = Pool::load(e);
        // @dev: Store the reserve to ledger manually
        let mut reserve = pool.load_reserve(e, asset, false);
        index = reserve.config.index;
        let reserve_config = storage::get_res_config(e, asset);
        require_valid_reserve_metadata_changes(e, &reserve_config, config);
        // if any of the IR parameters were changed reset the IR modifier
        if reserve_config.r_base != config.r_base
            || reserve_config.r_one != config.r_one
            || reserve_config.r_two != config.r_two
            || reserve_config.r_three != config.r_three
            || reserve_config.util != config.util
        {
            reserve.data.ir_mod = SCALAR_7;
        }
        reserve.store(e);
    } else {
        index = storage::push_res_list(e, asset);
        let init_data = ReserveData {
            b_rate: SCALAR_12,
            d_rate: SCALAR_12,
            ir_mod: SCALAR_7,
            d_supply: 0,
            b_supply: 0,
            last_time: e.ledger().timestamp(),
            backstop_credit: 0,
        };
        storage::set_res_data(e, asset, &init_data);
    }

    let reserve_config = ReserveConfig {
        index,
        decimals: config.decimals,
        c_factor: config.c_factor,
        l_factor: config.l_factor,
        util: config.util,
        max_util: config.max_util,
        r_base: config.r_base,
        r_one: config.r_one,
        r_two: config.r_two,
        r_three: config.r_three,
        reactivity: config.reactivity,
        supply_cap: config.supply_cap,
        enabled: config.enabled,
    };
    storage::set_res_config(e, asset, &reserve_config);

    index
}

#[allow(clippy::zero_prefixed_literal)]
fn require_valid_reserve_metadata(e: &Env, metadata: &ReserveConfig) {
    const SCALAR_7_U32: u32 = SCALAR_7 as u32;
    if metadata.decimals > 18
        || metadata.c_factor > SCALAR_7_U32
        || metadata.l_factor > SCALAR_7_U32
        || metadata.util > 0_9000000
        || (metadata.max_util > SCALAR_7_U32 || metadata.max_util <= metadata.util)
        || metadata.r_base >= 1_0000000
        || metadata.r_base < 0_0001000
        || (metadata.r_one > metadata.r_two || metadata.r_two > metadata.r_three)
        || (metadata.reactivity > 0_0001000)
    {
        panic_with_error!(e, PoolError::InvalidReserveMetadata);
    }
}

fn require_valid_reserve_metadata_changes(
    e: &Env,
    cur_config: &ReserveConfig,
    metadata: &ReserveConfig,
) {
    if cur_config.decimals != metadata.decimals
        || (cur_config.l_factor != 0 && metadata.l_factor == 0)
    {
        panic_with_error!(e, PoolError::InvalidReserveMetadata);
    }
}

fn require_valid_pool_config(e: &Env, config: &PoolConfig) {
    // ensure backstop is [0,1)
    if config.bstop_rate >= SCALAR_7 as u32 {
        panic_with_error!(e, PoolError::InvalidPoolConfigArgs);
    }

    // verify max positions is at least 2 and less than 2 * max reserves
    if config.max_positions < 2 || config.max_positions > 2 * MAX_RESERVES {
        panic_with_error!(&e, PoolError::InvalidPoolConfigArgs);
    }

    // verify min collateral is at least 0
    if config.min_collateral < 0 {
        panic_with_error!(&e, PoolError::InvalidPoolConfigArgs);
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::QueuedReserveInit;
    use crate::testutils;

    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};

    #[test]
    fn test_execute_initialize() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);

        let admin = Address::generate(&e);
        let name = String::from_str(&e, "pool_name");
        let oracle = Address::generate(&e);
        let bstop_rate: u32 = 0_1000000;
        let max_positions = 2;
        let min_collateral = 1_0000000;
        let backstop_address = Address::generate(&e);
        let blnd_id = Address::generate(&e);

        e.as_contract(&pool, || {
            execute_initialize(
                &e,
                &admin,
                &name,
                &oracle,
                &bstop_rate,
                &max_positions,
                &min_collateral,
                &backstop_address,
                &blnd_id,
            );

            assert_eq!(storage::get_admin(&e), admin);
            let pool_config = storage::get_pool_config(&e);
            assert_eq!(pool_config.oracle, oracle);
            assert_eq!(pool_config.bstop_rate, bstop_rate);
            assert_eq!(pool_config.min_collateral, min_collateral);
            assert_eq!(pool_config.max_positions, max_positions);
            assert_eq!(pool_config.status, 6);
            assert_eq!(storage::get_backstop(&e), backstop_address);
            assert_eq!(storage::get_blnd_token(&e), blnd_id);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1201)")]
    fn test_execute_initialize_bad_take_rate() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);

        let admin = Address::generate(&e);
        let name = String::from_str(&e, "pool_name");
        let oracle = Address::generate(&e);
        let bstop_rate = 1_0000000;
        let max_positions = 3;
        let min_collateral = 1_0000000;
        let backstop_address = Address::generate(&e);
        let blnd_id = Address::generate(&e);

        e.as_contract(&pool, || {
            execute_initialize(
                &e,
                &admin,
                &name,
                &oracle,
                &bstop_rate,
                &max_positions,
                &min_collateral,
                &backstop_address,
                &blnd_id,
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1201)")]
    fn test_execute_initialize_bad_max_positions() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);

        let admin = Address::generate(&e);
        let name = String::from_str(&e, "pool_name");
        let oracle = Address::generate(&e);
        let bstop_rate = 0_1000000;
        let max_positions = 1;
        let min_collateral = 1_0000000;
        let backstop_address = Address::generate(&e);
        let blnd_id = Address::generate(&e);

        e.as_contract(&pool, || {
            execute_initialize(
                &e,
                &admin,
                &name,
                &oracle,
                &bstop_rate,
                &max_positions,
                &min_collateral,
                &backstop_address,
                &blnd_id,
            );
        });
    }

    #[test]
    fn test_execute_update_pool() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            // happy path
            execute_update_pool(&e, 0_2000000, 4u32, 2_0000000);
            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.bstop_rate, 0_2000000);
            assert_eq!(new_pool_config.oracle, pool_config.oracle);
            assert_eq!(new_pool_config.status, pool_config.status);
            assert_eq!(new_pool_config.max_positions, 4u32);
            assert_eq!(new_pool_config.min_collateral, 2_0000000);
        });
    }

    #[test]
    fn test_execute_update_pool_updates_reserves_if_backstop_rate_changes() {
        let e = Env::default();
        e.mock_all_auths();

        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 123456,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let bombadil = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let (underlying_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_0, mut reserve_data_0) = testutils::default_reserve_meta();
        reserve_data_0.last_time = 12345;
        reserve_data_0.b_supply = 1000_0000000;
        reserve_data_0.d_supply = 750_0000000;
        reserve_config_0.index = 0;
        testutils::create_reserve(&e, &pool, &underlying_0, &reserve_config_0, &reserve_data_0);

        let (underlying_1, _) = testutils::create_token_contract(&e, &bombadil);
        let (mut reserve_config_1, mut reserve_data_1) = testutils::default_reserve_meta();
        reserve_data_1.last_time = 12345;
        reserve_data_1.b_supply = 250_0000000;
        reserve_data_1.d_supply = 100_5000000;
        reserve_config_1.index = 1;
        testutils::create_reserve(&e, &pool, &underlying_1, &reserve_config_1, &reserve_data_1);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };

        e.ledger().set(LedgerInfo {
            timestamp: 12345 * 5,
            protocol_version: 22,
            sequence_number: 123456,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            execute_update_pool(&e, 0_2000000, 4u32, 2_0000000);

            let new_pool_config = storage::get_pool_config(&e);
            assert_eq!(new_pool_config.bstop_rate, 0_2000000);
            assert_eq!(new_pool_config.oracle, pool_config.oracle);
            assert_eq!(new_pool_config.status, pool_config.status);
            assert_eq!(new_pool_config.max_positions, 4u32);
            assert_eq!(new_pool_config.min_collateral, 2_0000000);

            let new_reserve_data_0 = storage::get_res_data(&e, &underlying_0);
            assert_eq!(new_reserve_data_0.last_time, 12345 * 5);
            assert!(new_reserve_data_0.d_rate > reserve_data_0.d_rate);
            assert!(new_reserve_data_0.b_rate > reserve_data_0.b_rate);
            let new_reserve_data_1 = storage::get_res_data(&e, &underlying_1);
            assert_eq!(new_reserve_data_1.last_time, 12345 * 5);
            assert!(new_reserve_data_1.d_rate > reserve_data_1.d_rate);
            assert!(new_reserve_data_1.b_rate > reserve_data_1.b_rate);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1201)")]
    fn test_execute_update_pool_validates_b_stop_rate() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            execute_update_pool(&e, 1_0000000, 4u32, 1_0000000);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1201)")]
    fn test_execute_update_pool_validates_min_collateral() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            execute_update_pool(&e, 0_2000000, 4u32, -1);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1201)")]
    fn test_execute_update_pool_validates_max_positions() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            execute_update_pool(&e, 0_2000000, 1 + 2 * MAX_RESERVES, 2_0000000);
        });
    }

    #[test]
    fn test_queue_set_reserve_status_6() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 6,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);
            execute_queue_set_reserve(&e, &asset_id_0, &metadata);
            let queued_res = storage::get_queued_reserve_set(&e, &asset_id_0);
            let res_config_0 = queued_res.new_config;
            assert_eq!(res_config_0.decimals, metadata.decimals);
            assert_eq!(res_config_0.c_factor, metadata.c_factor);
            assert_eq!(res_config_0.l_factor, metadata.l_factor);
            assert_eq!(res_config_0.util, metadata.util);
            assert_eq!(res_config_0.r_base, metadata.r_base);
            assert_eq!(res_config_0.r_one, metadata.r_one);
            assert_eq!(res_config_0.r_one, metadata.r_one);
            assert_eq!(res_config_0.r_two, metadata.r_two);
            assert_eq!(res_config_0.r_three, metadata.r_three);
            assert_eq!(res_config_0.reactivity, metadata.reactivity);
            assert_eq!(res_config_0.index, 0);
            assert_eq!(queued_res.unlock_time, e.ledger().timestamp());
        });
    }

    #[test]
    fn test_queue_set_reserve() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);
            execute_queue_set_reserve(&e, &asset_id_0, &metadata);
            let queued_init = storage::get_queued_reserve_set(&e, &asset_id_0);
            assert_eq!(queued_init.new_config.decimals, metadata.decimals);
            assert_eq!(queued_init.new_config.c_factor, metadata.c_factor);
            assert_eq!(queued_init.new_config.l_factor, metadata.l_factor);
            assert_eq!(queued_init.new_config.util, metadata.util);
            assert_eq!(queued_init.new_config.max_util, metadata.max_util);
            assert_eq!(queued_init.new_config.r_base, metadata.r_base);
            assert_eq!(queued_init.new_config.r_one, metadata.r_one);
            assert_eq!(queued_init.new_config.r_two, metadata.r_two);
            assert_eq!(queued_init.new_config.r_three, metadata.r_three);
            assert_eq!(queued_init.new_config.reactivity, metadata.reactivity);
            assert_eq!(queued_init.new_config.index, 0);
            assert_eq!(
                queued_init.unlock_time,
                e.ledger().timestamp() + SECONDS_PER_WEEK
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1200)")]
    fn test_queue_set_reserve_duplicate() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 6,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);
            execute_queue_set_reserve(&e, &asset_id_0, &metadata);
            let queued_res = storage::get_queued_reserve_set(&e, &asset_id_0);
            let res_config_0 = queued_res.new_config;
            assert_eq!(res_config_0.index, 0);

            // try and queue the same reserve
            execute_queue_set_reserve(&e, &asset_id_0, &metadata);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_queue_set_reserve_validates_metadata() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);
        let (asset_id, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 1_7500000,
            util: 1_0000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);
            execute_queue_set_reserve(&e, &asset_id, &metadata);
        });
    }

    #[test]
    fn test_queue_set_reserve_with_existing_res() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let old_metadata = ReserveConfig {
            index: 1,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let metadata = ReserveConfig {
            index: 1,
            decimals: 7,
            c_factor: 0_6000000,
            l_factor: 0_5000000,
            util: 0_4000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 5,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);
            storage::set_res_config(&e, &asset_id_0, &old_metadata);
            execute_queue_set_reserve(&e, &asset_id_0, &metadata);
            let queued_init = storage::get_queued_reserve_set(&e, &asset_id_0);
            assert_eq!(queued_init.new_config.decimals, metadata.decimals);
            assert_eq!(queued_init.new_config.c_factor, metadata.c_factor);
            assert_eq!(queued_init.new_config.l_factor, metadata.l_factor);
            assert_eq!(queued_init.new_config.util, metadata.util);
            assert_eq!(queued_init.new_config.max_util, metadata.max_util);
            assert_eq!(queued_init.new_config.r_base, metadata.r_base);
            assert_eq!(queued_init.new_config.r_one, metadata.r_one);
            assert_eq!(queued_init.new_config.r_two, metadata.r_two);
            assert_eq!(queued_init.new_config.r_three, metadata.r_three);
            assert_eq!(queued_init.new_config.reactivity, metadata.reactivity);
            assert_eq!(queued_init.new_config.index, 1);
            assert_eq!(
                queued_init.unlock_time,
                e.ledger().timestamp() + SECONDS_PER_WEEK
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_queue_set_reserve_decimals_changed() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let old_metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let metadata = ReserveConfig {
            index: 0,
            decimals: 8,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 6,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);
            storage::set_res_config(&e, &asset_id_0, &old_metadata);
            execute_queue_set_reserve(&e, &asset_id_0, &metadata);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_queue_set_reserve_lf_removed() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let old_metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 6,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);
            storage::set_res_config(&e, &asset_id_0, &old_metadata);
            execute_queue_set_reserve(&e, &asset_id_0, &metadata);
        });
    }

    #[test]
    fn test_execute_cancel_queued_reserve_initialization() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        e.as_contract(&pool, || {
            storage::set_queued_reserve_set(
                &e,
                &QueuedReserveInit {
                    new_config: metadata.clone(),
                    unlock_time: e.ledger().timestamp(),
                },
                &asset_id_0,
            );
            execute_cancel_queued_set_reserve(&e, &asset_id_0);
            let result = storage::has_queued_reserve_set(&e, &asset_id_0);

            assert!(!result);
        });
    }

    #[test]
    fn test_execute_set_reserve_first_reserve() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        e.as_contract(&pool, || {
            storage::set_queued_reserve_set(
                &e,
                &QueuedReserveInit {
                    new_config: metadata.clone(),
                    unlock_time: e.ledger().timestamp(),
                },
                &asset_id_0,
            );
            execute_set_reserve(&e, &asset_id_0);
            let res_config_0: ReserveConfig = storage::get_res_config(&e, &asset_id_0);
            assert_eq!(res_config_0.decimals, metadata.decimals);
            assert_eq!(res_config_0.c_factor, metadata.c_factor);
            assert_eq!(res_config_0.l_factor, metadata.l_factor);
            assert_eq!(res_config_0.util, metadata.util);
            assert_eq!(res_config_0.max_util, metadata.max_util);
            assert_eq!(res_config_0.r_one, metadata.r_one);
            assert_eq!(res_config_0.r_two, metadata.r_two);
            assert_eq!(res_config_0.r_three, metadata.r_three);
            assert_eq!(res_config_0.reactivity, metadata.reactivity);
            assert_eq!(res_config_0.index, 0);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1203)")]
    fn test_execute_set_reserve_requires_block_passed() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        e.as_contract(&pool, || {
            storage::set_queued_reserve_set(
                &e,
                &QueuedReserveInit {
                    new_config: metadata.clone(),
                    unlock_time: e.ledger().timestamp() + 1,
                },
                &asset_id_0,
            );
            execute_set_reserve(&e, &asset_id_0);
        });
    }

    #[test]
    fn test_execute_set_reserve_update() {
        let e = Env::default();
        e.mock_all_auths();
        e.ledger().set(LedgerInfo {
            timestamp: 500,
            protocol_version: 22,
            sequence_number: 100,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (underlying, _) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, mut reserve_data) = testutils::default_reserve_meta();
        reserve_data.ir_mod = 1_001_000_000;
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        let mut new_metadata = reserve_config.clone();
        new_metadata.index = 123;
        new_metadata.c_factor += 1;
        new_metadata.l_factor += 1;
        new_metadata.max_util += 1;
        new_metadata.reactivity += 1;

        e.ledger().set(LedgerInfo {
            timestamp: 10000,
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
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            storage::set_queued_reserve_set(
                &e,
                &QueuedReserveInit {
                    new_config: new_metadata.clone(),
                    unlock_time: e.ledger().timestamp(),
                },
                &underlying,
            );
            execute_set_reserve(&e, &underlying);
            let res_config_updated = storage::get_res_config(&e, &underlying);
            assert_eq!(res_config_updated.decimals, new_metadata.decimals);
            assert_eq!(res_config_updated.c_factor, new_metadata.c_factor);
            assert_eq!(res_config_updated.l_factor, new_metadata.l_factor);
            assert_eq!(res_config_updated.util, new_metadata.util);
            assert_eq!(res_config_updated.max_util, new_metadata.max_util);
            assert_eq!(res_config_updated.r_base, new_metadata.r_base);
            assert_eq!(res_config_updated.r_one, new_metadata.r_one);
            assert_eq!(res_config_updated.r_two, new_metadata.r_two);
            assert_eq!(res_config_updated.r_three, new_metadata.r_three);
            assert_eq!(res_config_updated.reactivity, new_metadata.reactivity);
            assert_eq!(res_config_updated.index, reserve_config.index);

            // validate interest was accrued
            let res_data = storage::get_res_data(&e, &underlying);
            assert!(res_data.d_rate > 1_000_000_000_000);
            assert!(res_data.backstop_credit > 0);
            assert_eq!(res_data.last_time, 10000);
            assert!(res_data.ir_mod != 1_0000000);
        });
    }

    #[test]
    fn test_execute_set_reserve_update_resets_ir_mod() {
        let e = Env::default();
        e.mock_all_auths();
        e.ledger().set(LedgerInfo {
            timestamp: 500,
            protocol_version: 22,
            sequence_number: 100,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (underlying, _) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, mut reserve_data) = testutils::default_reserve_meta();
        reserve_data.ir_mod = 1_100_000_000;
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        let mut new_metadata = reserve_config.clone();
        new_metadata.r_base += 1;

        e.ledger().set(LedgerInfo {
            timestamp: 10000,
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
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            storage::set_queued_reserve_set(
                &e,
                &QueuedReserveInit {
                    new_config: new_metadata.clone(),
                    unlock_time: e.ledger().timestamp(),
                },
                &underlying,
            );
            execute_set_reserve(&e, &underlying);
            let res_config_updated = storage::get_res_config(&e, &underlying);
            assert_eq!(res_config_updated.decimals, new_metadata.decimals);
            assert_eq!(res_config_updated.c_factor, new_metadata.c_factor);
            assert_eq!(res_config_updated.l_factor, new_metadata.l_factor);
            assert_eq!(res_config_updated.util, new_metadata.util);
            assert_eq!(res_config_updated.max_util, new_metadata.max_util);
            assert_eq!(res_config_updated.r_base, new_metadata.r_base);
            assert_eq!(res_config_updated.r_one, new_metadata.r_one);
            assert_eq!(res_config_updated.r_two, new_metadata.r_two);
            assert_eq!(res_config_updated.r_three, new_metadata.r_three);
            assert_eq!(res_config_updated.reactivity, new_metadata.reactivity);
            assert_eq!(res_config_updated.index, reserve_config.index);

            let res_data = storage::get_res_data(&e, &underlying);
            assert!(res_data.d_rate > 1_000_000_000_000);
            assert!(res_data.backstop_credit > 0);
            assert_eq!(res_data.last_time, 10000);
            assert_eq!(res_data.ir_mod, 1_0000000);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_execute_set_reserve_validates_decimals_stay_same() {
        let e = Env::default();
        e.mock_all_auths();
        e.ledger().set(LedgerInfo {
            timestamp: 500,
            protocol_version: 22,
            sequence_number: 100,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (underlying, _) = testutils::create_token_contract(&e, &bombadil);
        let (reserve_config, reserve_data) = testutils::default_reserve_meta();
        testutils::create_reserve(&e, &pool, &underlying, &reserve_config, &reserve_data);

        let new_metadata = ReserveConfig {
            index: 99,
            decimals: 8, // started at 18
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_0777777,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 105,
            supply_cap: 1000000000000000000,
            enabled: true,
        };

        let pool_config = PoolConfig {
            oracle: Address::generate(&e),
            min_collateral: 1_0000000,
            bstop_rate: 0_1000000,
            status: 0,
            max_positions: 2,
        };
        e.as_contract(&pool, || {
            storage::set_pool_config(&e, &pool_config);

            storage::set_queued_reserve_set(
                &e,
                &QueuedReserveInit {
                    new_config: new_metadata.clone(),
                    unlock_time: e.ledger().timestamp(),
                },
                &underlying,
            );
            execute_set_reserve(&e, &underlying);
        });
    }

    #[test]
    fn test_initialize_reserve_sets_index() {
        let e = Env::default();
        e.mock_all_auths();
        let pool = testutils::create_pool(&e);
        let bombadil = Address::generate(&e);

        let (asset_id_0, _) = testutils::create_token_contract(&e, &bombadil);
        let (asset_id_1, _) = testutils::create_token_contract(&e, &bombadil);

        let metadata = ReserveConfig {
            index: 0,
            decimals: 7,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        e.as_contract(&pool, || {
            initialize_reserve(&e, &asset_id_0, &metadata);

            initialize_reserve(&e, &asset_id_1, &metadata);
            let res_config_0 = storage::get_res_config(&e, &asset_id_0);
            let res_config_1 = storage::get_res_config(&e, &asset_id_1);
            assert_eq!(res_config_0.decimals, metadata.decimals);
            assert_eq!(res_config_0.c_factor, metadata.c_factor);
            assert_eq!(res_config_0.l_factor, metadata.l_factor);
            assert_eq!(res_config_0.util, metadata.util);
            assert_eq!(res_config_0.max_util, metadata.max_util);
            assert_eq!(res_config_0.r_one, metadata.r_one);
            assert_eq!(res_config_0.r_two, metadata.r_two);
            assert_eq!(res_config_0.r_three, metadata.r_three);
            assert_eq!(res_config_0.reactivity, metadata.reactivity);
            assert_eq!(res_config_0.index, 0);
            assert_eq!(res_config_1.index, 1);
        });
    }

    #[test]
    fn test_validate_reserve_metadata() {
        let e = Env::default();

        // valid
        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0001000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
        // no panic
        assert!(true);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_decimals() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 19,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0001000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_c_factor() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 1_0000001,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0001000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_l_factor() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 1_0000001,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0001000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_util() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_9000001,
            max_util: 0_9500000,
            r_base: 0_0001000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_max_util() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 1_0000001,
            r_base: 0_0001000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_r_base_too_high() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 1_0000000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_r_base_too_low() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0000999,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_r_order() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0000100,
            r_one: 0_5000001,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 100,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1202)")]
    fn test_validate_reserve_metadata_validates_reactivity() {
        let e = Env::default();

        let metadata = ReserveConfig {
            index: 0,
            decimals: 18,
            c_factor: 0_7500000,
            l_factor: 0_7500000,
            util: 0_5000000,
            max_util: 0_9500000,
            r_base: 0_0100000,
            r_one: 0_0500000,
            r_two: 0_5000000,
            r_three: 1_5000000,
            reactivity: 0_0001001,
            supply_cap: 1000000000000000000,
            enabled: true,
        };
        require_valid_reserve_metadata(&e, &metadata);
    }
}
