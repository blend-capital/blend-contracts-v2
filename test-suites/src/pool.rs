mod pool_contract {
    soroban_sdk::contractimport!(file = "../target/wasm32-unknown-unknown/optimized/pool.wasm");
}
pub use pool_contract::WASM as POOL_WASM;

use pool::ReserveConfig;

pub fn default_reserve_metadata() -> ReserveConfig {
    ReserveConfig {
        decimals: 7,
        c_factor: 0_7500000,
        l_factor: 0_7500000,
        util: 0_7500000,
        max_util: 0_9500000,
        r_base: 0_0100000,
        r_one: 0_0500000,
        r_two: 0_5000000,
        r_three: 1_5000000,
        reactivity: 0_0000020, // 2e-6
        index: 0,
        supply_cap: 1000000000000000000,
        enabled: true,
    }
}
