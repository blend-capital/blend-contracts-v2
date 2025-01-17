use soroban_sdk::{
    contracttype, unwrap::UnwrapOptimized, vec, Address, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};

use crate::backstop::{PoolBalance, UserBalance};

/********** Ledger Thresholds **********/

const ONE_DAY_LEDGERS: u32 = 17280; // assumes 5s a ledger

const LEDGER_THRESHOLD_INSTANCE: u32 = ONE_DAY_LEDGERS * 30; // ~ 30 days
const LEDGER_BUMP_INSTANCE: u32 = LEDGER_THRESHOLD_INSTANCE + ONE_DAY_LEDGERS; // ~ 31 days

const LEDGER_THRESHOLD_SHARED: u32 = ONE_DAY_LEDGERS * 45; // ~ 45 days
const LEDGER_BUMP_SHARED: u32 = LEDGER_THRESHOLD_SHARED + ONE_DAY_LEDGERS; // ~ 46 days

const LEDGER_THRESHOLD_USER: u32 = ONE_DAY_LEDGERS * 100; // ~ 100 days
pub(crate) const LEDGER_BUMP_USER: u32 = LEDGER_THRESHOLD_USER + 20 * ONE_DAY_LEDGERS; // ~ 120 days

/********** Storage Types **********/

// The emission data for a reward zone pool
#[derive(Clone)]
#[contracttype]
pub struct RzEmissionData {
    pub index: i128,
    pub accrued: i128,
}

// The emission data for a pool's backstop
#[derive(Clone)]
#[contracttype]
pub struct BackstopEmissionData {
    // The expiration time of the backstop's emissions
    pub expiration: u64,
    // The earnings per share of the backstop (14 decimals)
    pub eps: u64,
    // The backstop's emission index (14 decimals)
    pub index: i128,
    // The last time the backstop's emissions were updated
    pub last_time: u64,
}

/// The user emission data for the reserve b or d token
#[derive(Clone)]
#[contracttype]
pub struct UserEmissionData {
    // The user's last accrued emission index (14 decimals)
    pub index: i128,
    pub accrued: i128,
}

/********** Storage Key Types **********/

const EMITTER_KEY: &str = "Emitter";
const BACKSTOP_TOKEN_KEY: &str = "BToken";
const POOL_FACTORY_KEY: &str = "PoolFact";
const BLND_TOKEN_KEY: &str = "BLNDTkn";
const USDC_TOKEN_KEY: &str = "USDCTkn";
const LAST_DISTRO_KEY: &str = "LastDist";
const REWARD_ZONE_KEY: &str = "RZ";
const DROP_LIST_KEY: &str = "DropList";
const LP_TOKEN_VAL_KEY: &str = "LPTknVal";
const RZ_EMISSION_INDEX_KEY: &str = "RZEmissionIndex";
const BACKFILL_EMISSIONS_KEY: &str = "BackfillEmis";
const BACKFILL_STATUS_KEY: &str = "Backfill";

#[derive(Clone)]
#[contracttype]
pub struct PoolUserKey {
    pool: Address,
    user: Address,
}

#[derive(Clone)]
#[contracttype]
pub enum BackstopDataKey {
    UserBalance(PoolUserKey),
    PoolBalance(Address),
    PoolUSDC(Address),
    RzEmisData(Address),
    BEmisData(Address),
    UEmisData(PoolUserKey),
}

/****************************
**         Storage         **
****************************/

/// Bump the instance rent for the contract
pub fn extend_instance(e: &Env) {
    e.storage()
        .instance()
        .extend_ttl(LEDGER_THRESHOLD_INSTANCE, LEDGER_BUMP_INSTANCE);
}

/// Fetch an entry in persistent storage that has a default value if it doesn't exist
fn get_persistent_default<K: IntoVal<Env, Val>, V: TryFromVal<Env, Val>, F: FnOnce() -> V>(
    e: &Env,
    key: &K,
    default: F,
    bump_threshold: u32,
    bump_amount: u32,
) -> V {
    if let Some(result) = e.storage().persistent().get::<K, V>(key) {
        e.storage()
            .persistent()
            .extend_ttl(key, bump_threshold, bump_amount);
        result
    } else {
        default()
    }
}

/********** Instance Storage **********/

/// Fetch the pool factory id
pub fn get_emitter(e: &Env) -> Address {
    e.storage()
        .instance()
        .get::<Symbol, Address>(&Symbol::new(e, EMITTER_KEY))
        .unwrap_optimized()
}

/// Set the pool factory
///
/// ### Arguments
/// * `pool_factory_id` - The ID of the pool factory
pub fn set_emitter(e: &Env, pool_factory_id: &Address) {
    e.storage()
        .instance()
        .set::<Symbol, Address>(&Symbol::new(e, EMITTER_KEY), pool_factory_id);
}

/// Fetch the pool factory id
pub fn get_pool_factory(e: &Env) -> Address {
    e.storage()
        .instance()
        .get::<Symbol, Address>(&Symbol::new(e, POOL_FACTORY_KEY))
        .unwrap_optimized()
}

/// Set the pool factory
///
/// ### Arguments
/// * `pool_factory_id` - The ID of the pool factory
pub fn set_pool_factory(e: &Env, pool_factory_id: &Address) {
    e.storage()
        .instance()
        .set::<Symbol, Address>(&Symbol::new(e, POOL_FACTORY_KEY), pool_factory_id);
}

/// Fetch the BLND token id
pub fn get_blnd_token(e: &Env) -> Address {
    e.storage()
        .instance()
        .get::<Symbol, Address>(&Symbol::new(e, BLND_TOKEN_KEY))
        .unwrap_optimized()
}

/// Set the BLND token id
///
/// ### Arguments
/// * `blnd_token_id` - The ID of the new BLND token
pub fn set_blnd_token(e: &Env, blnd_token_id: &Address) {
    e.storage()
        .instance()
        .set::<Symbol, Address>(&Symbol::new(e, BLND_TOKEN_KEY), blnd_token_id);
}

/// Fetch the USDC token id
pub fn get_usdc_token(e: &Env) -> Address {
    e.storage()
        .instance()
        .get::<Symbol, Address>(&Symbol::new(e, USDC_TOKEN_KEY))
        .unwrap_optimized()
}

/// Set the USDC token id
///
/// ### Arguments
/// * `usdc_token_id` - The ID of the new USDC token
pub fn set_usdc_token(e: &Env, usdc_token_id: &Address) {
    e.storage()
        .instance()
        .set::<Symbol, Address>(&Symbol::new(e, USDC_TOKEN_KEY), usdc_token_id);
}

/// Fetch the backstop token id
pub fn get_backstop_token(e: &Env) -> Address {
    e.storage()
        .instance()
        .get::<Symbol, Address>(&Symbol::new(e, BACKSTOP_TOKEN_KEY))
        .unwrap_optimized()
}

/// Set the backstop token id
///
/// ### Arguments
/// * `backstop_token_id` - The ID of the new backstop token
pub fn set_backstop_token(e: &Env, backstop_token_id: &Address) {
    e.storage()
        .instance()
        .set::<Symbol, Address>(&Symbol::new(e, BACKSTOP_TOKEN_KEY), backstop_token_id);
}

/********** User Shares **********/

/// Fetch the balance's for a given user
///
/// ### Arguments
/// * `pool` - The pool the balance is associated with
/// * `user` - The owner of the deposit
pub fn get_user_balance(e: &Env, pool: &Address, user: &Address) -> UserBalance {
    let key = BackstopDataKey::UserBalance(PoolUserKey {
        pool: pool.clone(),
        user: user.clone(),
    });
    get_persistent_default(
        e,
        &key,
        || UserBalance {
            shares: 0,
            q4w: vec![&e],
        },
        LEDGER_THRESHOLD_USER,
        LEDGER_BUMP_USER,
    )
}

/// Set share balance for a user deposit in a pool
///
/// ### Arguments
/// * `pool` - The pool the balance is associated with
/// * `user` - The owner of the deposit
/// * `balance` - The user balance
pub fn set_user_balance(e: &Env, pool: &Address, user: &Address, balance: &UserBalance) {
    let key = BackstopDataKey::UserBalance(PoolUserKey {
        pool: pool.clone(),
        user: user.clone(),
    });
    e.storage()
        .persistent()
        .set::<BackstopDataKey, UserBalance>(&key, balance);
}

/********** Pool Balance **********/

/// Fetch the balances for a given pool
///
/// ### Arguments
/// * `pool` - The pool the deposit is associated with
pub fn get_pool_balance(e: &Env, pool: &Address) -> PoolBalance {
    let key = BackstopDataKey::PoolBalance(pool.clone());
    get_persistent_default(
        e,
        &key,
        || PoolBalance {
            shares: 0,
            tokens: 0,
            q4w: 0,
        },
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the balances for a pool
///
/// ### Arguments
/// * `pool` - The pool the deposit is associated with
/// * `balance` - The pool balances
pub fn set_pool_balance(e: &Env, pool: &Address, balance: &PoolBalance) {
    let key = BackstopDataKey::PoolBalance(pool.clone());
    e.storage()
        .persistent()
        .set::<BackstopDataKey, PoolBalance>(&key, balance);
    e.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD_SHARED, LEDGER_BUMP_SHARED);
}

/********** Distribution / Reward Zone **********/

/// Get the timestamp of when the next emission cycle begins
pub fn get_last_distribution_time(e: &Env) -> u64 {
    get_persistent_default(
        e,
        &Symbol::new(e, LAST_DISTRO_KEY),
        || 0u64,
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the timestamp of when the next emission cycle begins
///
/// ### Arguments
/// * `timestamp` - The timestamp the distribution window will open
pub fn set_last_distribution_time(e: &Env, timestamp: &u64) {
    e.storage()
        .persistent()
        .set::<Symbol, u64>(&Symbol::new(e, LAST_DISTRO_KEY), timestamp);
    e.storage().persistent().extend_ttl(
        &Symbol::new(e, LAST_DISTRO_KEY),
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    );
}

/// Get the current pool addresses that are in the reward zone
pub fn get_reward_zone(e: &Env) -> Vec<Address> {
    get_persistent_default(
        e,
        &Symbol::new(e, REWARD_ZONE_KEY),
        || vec![e],
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the reward zone
///
/// ### Arguments
/// * `reward_zone` - The vector of pool addresses that comprise the reward zone
pub fn set_reward_zone(e: &Env, reward_zone: &Vec<Address>) {
    e.storage()
        .persistent()
        .set::<Symbol, Vec<Address>>(&Symbol::new(e, REWARD_ZONE_KEY), reward_zone);
    e.storage().persistent().extend_ttl(
        &Symbol::new(e, REWARD_ZONE_KEY),
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    );
}

/// Get the current total backfill emissions
pub fn get_backfill_emissions(e: &Env) -> i128 {
    get_persistent_default(
        e,
        &Symbol::new(e, BACKFILL_EMISSIONS_KEY),
        || 0i128,
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the current total backfill emissions
///
/// ### Arguments
/// * `emissions` - The total emissions currently needed to fulfill all backfilled emissions
pub fn set_backfill_emissions(e: &Env, emissions: &i128) {
    e.storage()
        .persistent()
        .set::<Symbol, i128>(&Symbol::new(e, BACKFILL_EMISSIONS_KEY), emissions);
    e.storage().persistent().extend_ttl(
        &Symbol::new(e, BACKFILL_EMISSIONS_KEY),
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    );
}

/// Get the current total backfill status
///
/// None if no status has been recorded, otherwise the current status
pub fn get_backfill_status(e: &Env) -> Option<bool> {
    get_persistent_default(
        e,
        &Symbol::new(e, BACKFILL_STATUS_KEY),
        || None,
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the current backfill status
///
/// ### Arguments
/// * `status` - True if the backfill emissions are currently active, false otherwise
pub fn set_backfill_status(e: &Env, status: &bool) {
    e.storage()
        .persistent()
        .set::<Symbol, bool>(&Symbol::new(e, BACKFILL_STATUS_KEY), status);
    e.storage().persistent().extend_ttl(
        &Symbol::new(e, BACKFILL_STATUS_KEY),
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    );
}

/********** Backstop Depositor Emissions **********/

/// Get the reward zone emission index
/// The index is used to calculate the amount of tokens to distribute to the backstop
pub fn get_rz_emission_index(e: &Env) -> i128 {
    get_persistent_default(
        e,
        &Symbol::new(&e, RZ_EMISSION_INDEX_KEY),
        || 0i128,
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the reward zone emission index
/// The index is used to calculate the amount of tokens to distribute to the backstop
///
/// ### Arguments
/// * 'index' - The index of the backstop's emissions
pub fn set_rz_emission_index(e: &Env, index: &i128) {
    e.storage()
        .persistent()
        .set::<Symbol, i128>(&Symbol::new(&e, RZ_EMISSION_INDEX_KEY), index);
    e.storage().persistent().extend_ttl(
        &Symbol::new(&e, RZ_EMISSION_INDEX_KEY),
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    );
}

/// Get the emission data for the reward zone pool
///
/// ### Arguments
/// * `pool` - The pool
pub fn get_rz_emis_data(e: &Env, pool: &Address) -> Option<RzEmissionData> {
    let key = BackstopDataKey::RzEmisData(pool.clone());
    get_persistent_default(
        e,
        &key,
        || None,
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the emission data for the reward zone pool
///
/// ### Arguments
/// * `pool` - The pool
/// * `index` - The index of the backstop's emissions
pub fn set_rz_emis_data(e: &Env, pool: &Address, emis_data: &RzEmissionData) {
    let key = BackstopDataKey::RzEmisData(pool.clone());
    e.storage()
        .persistent()
        .set::<BackstopDataKey, RzEmissionData>(&key, emis_data);
    e.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD_SHARED, LEDGER_BUMP_SHARED);
}

/// Get the pool's backstop emissions data
///
/// ### Arguments
/// * `pool` - The pool
pub fn get_backstop_emis_data(e: &Env, pool: &Address) -> Option<BackstopEmissionData> {
    let key = BackstopDataKey::BEmisData(pool.clone());
    get_persistent_default(
        e,
        &key,
        || None,
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    )
}

/// Set the pool's backstop emissions data
///
/// ### Arguments
/// * `pool` - The pool
/// * `backstop_emis_data` - The new emission data for the backstop
pub fn set_backstop_emis_data(e: &Env, pool: &Address, backstop_emis_data: &BackstopEmissionData) {
    let key = BackstopDataKey::BEmisData(pool.clone());
    e.storage()
        .persistent()
        .set::<BackstopDataKey, BackstopEmissionData>(&key, backstop_emis_data);
}

/// Get the user's backstop emissions data
///
/// ### Arguments
/// * `pool` - The pool whose backstop the user's emissions are for
/// * `user` - The user's address
pub fn get_user_emis_data(e: &Env, pool: &Address, user: &Address) -> Option<UserEmissionData> {
    let key = BackstopDataKey::UEmisData(PoolUserKey {
        pool: pool.clone(),
        user: user.clone(),
    });
    get_persistent_default(e, &key, || None, LEDGER_THRESHOLD_USER, LEDGER_BUMP_USER)
}

/// Set the user's backstop emissions data
///
/// ### Arguments
/// * `pool` - The pool whose backstop the user's emissions are for
/// * `user` - The user's address
/// * `user_emis_data` - The new emission data for the user
pub fn set_user_emis_data(
    e: &Env,
    pool: &Address,
    user: &Address,
    user_emis_data: &UserEmissionData,
) {
    let key = BackstopDataKey::UEmisData(PoolUserKey {
        pool: pool.clone(),
        user: user.clone(),
    });
    e.storage()
        .persistent()
        .set::<BackstopDataKey, UserEmissionData>(&key, user_emis_data);
}

/********** Drop Emissions **********/

/// Get the current pool addresses that are in the drop list and the amount of the initial distribution they receive
pub fn get_drop_list(e: &Env) -> Vec<(Address, i128)> {
    e.storage()
        .persistent()
        .get::<Symbol, Vec<(Address, i128)>>(&Symbol::new(&e, DROP_LIST_KEY))
        .unwrap_optimized()
}

/// Set the drop list
///
/// ### Arguments
/// * `drop_list` - The map of pool addresses to the amount of the initial distribution they receive
pub fn set_drop_list(e: &Env, drop_list: &Vec<(Address, i128)>) {
    e.storage()
        .persistent()
        .set::<Symbol, Vec<(Address, i128)>>(&Symbol::new(&e, DROP_LIST_KEY), drop_list);
    e.storage().persistent().extend_ttl(
        &Symbol::new(&e, DROP_LIST_KEY),
        LEDGER_THRESHOLD_USER,
        LEDGER_BUMP_USER,
    );
}

/********** LP Token Value **********/

/// Get the last updated token value for the LP pool
pub fn get_lp_token_val(e: &Env) -> (i128, i128) {
    e.storage().persistent().extend_ttl(
        &Symbol::new(&e, LP_TOKEN_VAL_KEY),
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    );
    e.storage()
        .persistent()
        .get::<Symbol, (i128, i128)>(&Symbol::new(&e, LP_TOKEN_VAL_KEY))
        .unwrap_optimized()
}

/// Set the reward zone
///
/// ### Arguments
/// * `share_val` - A tuple of (blnd_per_share, usdc_per_share)
pub fn set_lp_token_val(e: &Env, share_val: &(i128, i128)) {
    e.storage()
        .persistent()
        .set::<Symbol, (i128, i128)>(&Symbol::new(&e, LP_TOKEN_VAL_KEY), share_val);
    e.storage().persistent().extend_ttl(
        &Symbol::new(&e, LP_TOKEN_VAL_KEY),
        LEDGER_THRESHOLD_SHARED,
        LEDGER_BUMP_SHARED,
    );
}
