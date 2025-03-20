use soroban_fixed_point_math::SorobanFixedPoint;
use soroban_sdk::{contracttype, panic_with_error, Address, Env, Map};

use crate::{constants::SCALAR_12, emissions, storage, validator::require_nonnegative, PoolError};

use super::{Pool, Reserve};

/// A user / contracts position's with the pool, stored in the Reserve's decimals
#[derive(Clone)]
#[contracttype]
pub struct Positions {
    pub liabilities: Map<u32, i128>, // Map of Reserve Index to liability share balance
    pub collateral: Map<u32, i128>,  // Map of Reserve Index to collateral supply share balance
    pub supply: Map<u32, i128>,      // Map of Reserve Index to non-collateral supply share balance
}

impl Positions {
    /// Create an empty Positions object in the environment
    pub fn env_default(e: &Env) -> Self {
        Positions {
            liabilities: Map::new(e),
            collateral: Map::new(e),
            supply: Map::new(e),
        }
    }

    /// Get the number of effective (impacts health factor) posiitons the user holds.
    ///
    /// This function ignores non-collateralized supply positions, as they are not relevant to the
    /// max number of allowed positions by the pool.
    pub fn effective_count(&self) -> u32 {
        self.liabilities.len() + self.collateral.len()
    }
}

/// A user / contracts position's with the pool
#[derive(Clone)]
pub struct User {
    pub address: Address,
    pub positions: Positions,
}

impl User {
    /// Create an empty User object in the environment
    pub fn load(e: &Env, address: &Address) -> Self {
        User {
            address: address.clone(),
            positions: storage::get_user_positions(e, address),
        }
    }

    /// Store the user's positions to the ledger
    pub fn store(&self, e: &Env) {
        storage::set_user_positions(e, &self.address, &self.positions);
    }

    /// Check if the user has liabilities
    pub fn has_liabilities(&self) -> bool {
        !self.positions.liabilities.is_empty()
    }

    /// Get the debtToken position for the reserve at the given index
    pub fn get_liabilities(&self, reserve_index: u32) -> i128 {
        self.positions.liabilities.get(reserve_index).unwrap_or(0)
    }

    /// Add liabilities to the position expressed in debtTokens. Accrues emissions
    /// against the balance if necessary and updates the reserve's d_supply.
    pub fn add_liabilities(&mut self, e: &Env, reserve: &mut Reserve, amount: i128) {
        if amount <= 0 {
            panic_with_error!(e, PoolError::InvalidDTokenMintAmount)
        }
        let balance = self.get_liabilities(reserve.config.index);
        self.update_d_emissions(e, reserve, balance);
        self.positions
            .liabilities
            .set(reserve.config.index, balance + amount);
        reserve.data.d_supply += amount;
    }

    /// Remove liabilities from the position expressed in debtTokens. Accrues emissions
    /// against the balance if necessary and updates the reserve's d_supply.
    pub fn remove_liabilities(&mut self, e: &Env, reserve: &mut Reserve, amount: i128) {
        if amount <= 0 {
            panic_with_error!(e, PoolError::InvalidDTokenBurnAmount)
        }
        let balance = self.get_liabilities(reserve.config.index);
        self.update_d_emissions(e, reserve, balance);
        let new_balance = balance - amount;
        require_nonnegative(e, &new_balance);
        if new_balance == 0 {
            self.positions.liabilities.remove(reserve.config.index);
        } else {
            self.positions
                .liabilities
                .set(reserve.config.index, new_balance);
        }
        reserve.data.d_supply -= amount;
    }

    /// Default on liabilities from the position expressed in debtTokens. Accrues emissions
    /// against the balance if necessary and updates the reserve's b_rate and d_supply.
    ///
    /// This should only be called if the liabilities are being defaulted on. The liability will
    /// be forgiven and suppliers will lose funds.
    pub fn default_liabilities(&mut self, e: &Env, reserve: &mut Reserve, amount: i128) {
        self.remove_liabilities(e, reserve, amount);
        // determine amount of funds in underlying that have defaulted
        // and deduct them from the b_rate
        let default_amount = reserve.to_asset_from_d_token(e, amount);
        let b_rate_loss = default_amount.fixed_div_ceil(&e, &reserve.data.b_supply, &SCALAR_12);
        reserve.data.b_rate -= b_rate_loss;
        if reserve.data.b_rate < 0 {
            reserve.data.b_rate = 0;
        }
    }

    /// Check if the user has collateral
    pub fn has_collateral(&self) -> bool {
        !self.positions.collateral.is_empty()
    }

    /// Get the collateralized blendToken position for the reserve at the given index
    pub fn get_collateral(&self, reserve_index: u32) -> i128 {
        self.positions.collateral.get(reserve_index).unwrap_or(0)
    }

    /// Add collateral to the position expressed in blendTokens. Accrues emissions
    /// against the balance if necessary and updates the reserve's b_supply.
    pub fn add_collateral(&mut self, e: &Env, reserve: &mut Reserve, amount: i128) {
        if amount <= 0 {
            panic_with_error!(e, PoolError::InvalidBTokenMintAmount)
        }
        let balance = self.get_collateral(reserve.config.index);
        self.update_b_emissions(e, reserve, self.get_total_supply(reserve.config.index));
        self.positions
            .collateral
            .set(reserve.config.index, balance + amount);
        reserve.data.b_supply += amount;
    }

    /// Remove collateral from the position expressed in blendTokens. Accrues emissions
    /// against the balance if necessary and updates the reserve's d_supply.
    pub fn remove_collateral(&mut self, e: &Env, reserve: &mut Reserve, amount: i128) {
        if amount <= 0 {
            panic_with_error!(e, PoolError::InvalidBTokenBurnAmount)
        }
        let balance = self.get_collateral(reserve.config.index);
        self.update_b_emissions(e, reserve, self.get_total_supply(reserve.config.index));
        let new_balance = balance - amount;
        require_nonnegative(e, &new_balance);
        if new_balance == 0 {
            self.positions.collateral.remove(reserve.config.index);
        } else {
            self.positions
                .collateral
                .set(reserve.config.index, new_balance);
        }
        reserve.data.b_supply -= amount;
    }

    /// Get the uncollateralized blendToken position for the reserve at the given index
    pub fn get_supply(&self, reserve_index: u32) -> i128 {
        self.positions.supply.get(reserve_index).unwrap_or(0)
    }

    /// Add supply to the position expressed in blendTokens. Accrues emissions
    /// against the balance if necessary and updates the reserve's b_supply.
    pub fn add_supply(&mut self, e: &Env, reserve: &mut Reserve, amount: i128) {
        if amount <= 0 {
            panic_with_error!(e, PoolError::InvalidBTokenMintAmount)
        }
        let balance = self.get_supply(reserve.config.index);
        self.update_b_emissions(e, reserve, self.get_total_supply(reserve.config.index));
        self.positions
            .supply
            .set(reserve.config.index, balance + amount);
        reserve.data.b_supply += amount;
    }

    /// Remove supply from the position expressed in blendTokens. Accrues emissions
    /// against the balance if necessary and updates the reserve's b_supply.
    pub fn remove_supply(&mut self, e: &Env, reserve: &mut Reserve, amount: i128) {
        if amount <= 0 {
            panic_with_error!(e, PoolError::InvalidBTokenBurnAmount)
        }
        let balance = self.get_supply(reserve.config.index);
        self.update_b_emissions(e, reserve, self.get_total_supply(reserve.config.index));
        let new_balance = balance - amount;
        require_nonnegative(e, &new_balance);
        if new_balance == 0 {
            self.positions.supply.remove(reserve.config.index);
        } else {
            self.positions.supply.set(reserve.config.index, new_balance);
        }
        reserve.data.b_supply -= amount;
    }

    /// Get the total supply and collateral of blendTokens for the user at the given index
    pub fn get_total_supply(&self, reserve_index: u32) -> i128 {
        self.get_collateral(reserve_index) + self.get_supply(reserve_index)
    }

    /// Removes positions from a user - does not consider supply
    pub fn rm_positions(
        &mut self,
        e: &Env,
        pool: &mut Pool,
        collateral_amounts: Map<Address, i128>,
        liability_amounts: Map<Address, i128>,
    ) {
        for (asset, amount) in collateral_amounts.iter() {
            if amount > 0 {
                let mut reserve = pool.load_reserve(e, &asset, true);
                self.remove_collateral(e, &mut reserve, amount);
                pool.cache_reserve(reserve);
            }
        }
        for (asset, amount) in liability_amounts.iter() {
            if amount > 0 {
                let mut reserve = pool.load_reserve(e, &asset, true);
                self.remove_liabilities(e, &mut reserve, amount);
                pool.cache_reserve(reserve);
            }
        }
    }

    /// Adds positions to a user - does not consider supply
    pub fn add_positions(
        &mut self,
        e: &Env,
        pool: &mut Pool,
        collateral_amounts: Map<Address, i128>,
        liability_amounts: Map<Address, i128>,
    ) {
        for (asset, amount) in collateral_amounts.iter() {
            if amount > 0 {
                let mut reserve = pool.load_reserve(e, &asset, true);
                self.add_collateral(e, &mut reserve, amount);
                pool.cache_reserve(reserve);
            }
        }
        for (asset, amount) in liability_amounts.iter() {
            if amount > 0 {
                let mut reserve = pool.load_reserve(e, &asset, true);
                self.add_liabilities(e, &mut reserve, amount);
                pool.cache_reserve(reserve);
            }
        }
    }

    fn update_d_emissions(&self, e: &Env, reserve: &Reserve, amount: i128) {
        emissions::update_emissions(
            e,
            reserve.config.index * 2,
            reserve.data.d_supply,
            reserve.scalar,
            &self.address,
            amount,
        );
    }

    fn update_b_emissions(&self, e: &Env, reserve: &Reserve, amount: i128) {
        emissions::update_emissions(
            e,
            reserve.config.index * 2 + 1,
            reserve.data.b_supply,
            reserve.scalar,
            &self.address,
            amount,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::SCALAR_7, storage, testutils, ReserveEmissionData, UserEmissionData};
    use soroban_fixed_point_math::SorobanFixedPoint;
    use soroban_sdk::{
        map,
        testutils::{Address as _, Ledger, LedgerInfo},
    };

    #[test]
    fn test_load_and_store() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let user = User {
            address: samwise.clone(),
            positions: Positions {
                collateral: map![&e, (0, 10000)],
                liabilities: map![&e],
                supply: map![&e],
            },
        };
        e.as_contract(&pool, || {
            user.store(&e);
            let loaded_user = User::load(&e, &samwise);
            assert_eq!(loaded_user.address, samwise);
            assert_eq!(loaded_user.positions.collateral.len(), 1);
            assert_eq!(loaded_user.positions.collateral.get_unchecked(0), 10000);
            assert_eq!(loaded_user.positions.liabilities.len(), 0);
            assert_eq!(loaded_user.positions.supply.len(), 0);
        });
    }

    #[test]
    fn test_liabilities() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_d_supply_0 = reserve_0.data.d_supply;

        let mut reserve_1 = testutils::default_reserve(&e);
        reserve_1.config.index = 1;
        let starting_d_supply_1 = reserve_1.data.d_supply;

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_liabilities(0), 0);
            assert_eq!(user.has_liabilities(), false);

            user.add_liabilities(&e, &mut reserve_0, 123);
            assert_eq!(user.get_liabilities(0), 123);
            assert_eq!(reserve_0.data.d_supply, starting_d_supply_0 + 123);
            assert_eq!(user.has_liabilities(), true);

            user.add_liabilities(&e, &mut reserve_1, 456);
            assert_eq!(user.get_liabilities(0), 123);
            assert_eq!(user.get_liabilities(1), 456);
            assert_eq!(reserve_1.data.d_supply, starting_d_supply_1 + 456);

            user.remove_liabilities(&e, &mut reserve_1, 100);
            assert_eq!(user.get_liabilities(1), 356);
            assert_eq!(reserve_1.data.d_supply, starting_d_supply_1 + 356);

            user.remove_liabilities(&e, &mut reserve_1, 356);
            assert_eq!(user.get_liabilities(1), 0);
            assert_eq!(user.positions.liabilities.len(), 1);
            assert_eq!(reserve_1.data.d_supply, starting_d_supply_1);

            user.remove_liabilities(&e, &mut reserve_0, 123);
            assert_eq!(user.get_liabilities(0), 0);
            assert_eq!(user.positions.liabilities.len(), 0);
            assert_eq!(reserve_0.data.d_supply, starting_d_supply_0);
            assert_eq!(user.has_liabilities(), false);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1218)")]
    fn test_add_liabilities_zero_mint() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_liabilities(0), 0);

            user.add_liabilities(&e, &mut reserve_0, 0);
        });
    }

    #[test]
    fn test_add_liabilities_accrues_emissions() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 10001000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_d_supply_0 = reserve_0.data.d_supply;

        let emis_res_data = ReserveEmissionData {
            expiration: 20000000,
            eps: 0_10000000000000,
            index: 10000000000,
            last_time: 10000000, // 1000s elapsed
        };
        let emis_user_data = UserEmissionData {
            index: 9000000000,
            accrued: 0,
        };

        let mut user = User {
            address: samwise.clone(),
            positions: Positions {
                liabilities: map![&e, (reserve_0.config.index, 1000)],
                collateral: map![&e],
                supply: map![&e],
            },
        };

        e.as_contract(&pool, || {
            let res_0_d_token_index = reserve_0.config.index * 2 + 0;
            storage::set_res_emis_data(&e, &res_0_d_token_index, &emis_res_data);
            storage::set_user_emissions(&e, &samwise, &res_0_d_token_index, &emis_user_data);

            user.add_liabilities(&e, &mut reserve_0, 123);
            assert_eq!(user.get_liabilities(0), 1123);
            assert_eq!(reserve_0.data.d_supply, starting_d_supply_0 + 123);

            let new_emis_res_data = storage::get_res_emis_data(&e, &res_0_d_token_index).unwrap();
            let new_index = 10000000000
                + (1000i128 * 0_10000000000000).fixed_div_floor(
                    &e,
                    &starting_d_supply_0,
                    &SCALAR_7,
                );
            assert_eq!(new_emis_res_data.last_time, 10001000);
            assert_eq!(new_emis_res_data.index, new_index);
            let user_emis_data =
                storage::get_user_emissions(&e, &samwise, &res_0_d_token_index).unwrap();
            let new_accrual = 0
                + (new_index - emis_user_data.index).fixed_mul_floor(
                    &e,
                    &1000,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(user_emis_data.accrued, new_accrual);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1219)")]
    fn test_remove_liabilities_zero_burn() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_liabilities(0), 0);

            user.add_liabilities(&e, &mut reserve_0, 123);
            assert_eq!(user.get_liabilities(0), 123);

            user.remove_liabilities(&e, &mut reserve_0, 0);
        });
    }

    #[test]
    fn test_remove_liabilities_accrues_emissions() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 10001000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_d_supply_0 = reserve_0.data.d_supply;

        let emis_res_data = ReserveEmissionData {
            expiration: 20000000,
            eps: 0_10000000000000,
            index: 10000000000,
            last_time: 10000000, // 1000s elapsed
        };
        let emis_user_data = UserEmissionData {
            index: 9000000000,
            accrued: 0,
        };
        let mut user = User {
            address: samwise.clone(),
            positions: Positions {
                liabilities: map![&e, (reserve_0.config.index, 1000)],
                collateral: map![&e],
                supply: map![&e],
            },
        };
        e.as_contract(&pool, || {
            let res_0_d_token_index = reserve_0.config.index * 2 + 0;
            storage::set_res_emis_data(&e, &res_0_d_token_index, &emis_res_data);
            storage::set_user_emissions(&e, &samwise, &res_0_d_token_index, &emis_user_data);

            user.remove_liabilities(&e, &mut reserve_0, 123);
            assert_eq!(user.get_liabilities(0), 877);
            assert_eq!(reserve_0.data.d_supply, starting_d_supply_0 - 123);

            let new_emis_res_data = storage::get_res_emis_data(&e, &res_0_d_token_index).unwrap();
            let new_index = 10000000000
                + (1000i128 * 0_1000000).fixed_div_floor(
                    &e,
                    &starting_d_supply_0,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(new_emis_res_data.last_time, 10001000);
            assert_eq!(new_emis_res_data.index, new_index);
            let user_emis_data =
                storage::get_user_emissions(&e, &samwise, &res_0_d_token_index).unwrap();
            let new_accrual = 0
                + (new_index - emis_user_data.index).fixed_mul_floor(
                    &e,
                    &1000,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(user_emis_data.accrued, new_accrual);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #8)")]
    fn test_remove_liabilities_over_balance_panics() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);
        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            user.add_liabilities(&e, &mut reserve_0, 123);
            assert_eq!(user.get_liabilities(0), 123);

            user.remove_liabilities(&e, &mut reserve_0, 124);
        });
    }

    #[test]
    fn test_default_liabilities_reduces_b_rate() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);
        reserve_0.data.d_rate = 1_500_000_000_000;
        reserve_0.data.d_supply = 500_0000000;
        reserve_0.data.b_rate = 1_250_000_000_000;
        reserve_0.data.b_supply = 750_0000000;

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_liabilities(0), 0);

            user.add_liabilities(&e, &mut reserve_0, 20_0000000);
            assert_eq!(user.get_liabilities(0), 20_0000000);

            let d_supply = reserve_0.data.d_supply;
            let total_supply = reserve_0.total_supply(&e);
            let underlying_default_amount = reserve_0.to_asset_from_d_token(&e, 20_0000000);
            user.default_liabilities(&e, &mut reserve_0, 20_0000000);

            assert_eq!(user.get_liabilities(0), 0);
            assert_eq!(reserve_0.data.d_supply, d_supply - 20_0000000);
            assert_eq!(
                reserve_0.total_supply(&e),
                total_supply - underlying_default_amount
            );
            assert_eq!(reserve_0.data.b_rate, 1_210_000_000_000);
            assert_eq!(reserve_0.data.b_supply, 750_0000000);
        });
    }

    #[test]
    fn test_default_liabilities_reduces_b_rate_to_zero() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);
        reserve_0.data.d_rate = 1_500_000_000_000;
        reserve_0.data.d_supply = 500_0000000;
        reserve_0.data.b_rate = 0_100_000_000_000;
        reserve_0.data.b_supply = 750_0000000;

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_liabilities(0), 0);

            user.add_liabilities(&e, &mut reserve_0, 100_0000000);
            assert_eq!(user.get_liabilities(0), 100_0000000);

            let d_supply = reserve_0.data.d_supply;
            user.default_liabilities(&e, &mut reserve_0, 100_0000000);

            assert_eq!(user.get_liabilities(0), 0);
            assert_eq!(reserve_0.data.d_supply, d_supply - 100_0000000);
            assert_eq!(reserve_0.total_supply(&e), 0);
            assert_eq!(reserve_0.data.b_rate, 0);
            assert_eq!(reserve_0.data.b_supply, 750_0000000);
        });
    }

    #[test]
    fn test_default_liabilities_reduces_b_rate_rounds_ceil() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);
        reserve_0.data.d_rate = 1_500_000_000_000;
        reserve_0.data.d_supply = 500_0000000;
        reserve_0.data.b_rate = 1_250_000_000_000;
        reserve_0.data.b_supply = 750_0000000;

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_liabilities(0), 0);

            user.add_liabilities(&e, &mut reserve_0, 20_0000001);
            assert_eq!(user.get_liabilities(0), 20_0000001);

            let d_supply = reserve_0.data.d_supply;
            let total_supply = reserve_0.total_supply(&e);
            let underlying_default_amount = reserve_0.to_asset_from_d_token(&e, 20_0000001);
            user.default_liabilities(&e, &mut reserve_0, 20_0000001);

            // rounding loss of 1 stroop for resulting total supply
            assert_eq!(user.get_liabilities(0), 0);
            assert_eq!(reserve_0.data.d_supply, d_supply - 20_0000001);
            assert_eq!(
                reserve_0.total_supply(&e),
                total_supply - underlying_default_amount - 1
            );
            assert_eq!(reserve_0.data.b_rate, 1_209_999_999_733);
            assert_eq!(reserve_0.data.b_supply, 750_0000000);
        });
    }

    #[test]
    fn test_collateral() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_b_supply_0 = reserve_0.data.b_supply;

        let mut reserve_1 = testutils::default_reserve(&e);
        reserve_1.config.index = 1;
        let starting_b_supply_1 = reserve_1.data.b_supply;

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_collateral(0), 0);
            assert_eq!(user.has_collateral(), false);

            user.add_collateral(&e, &mut reserve_0, 123);
            assert_eq!(user.get_collateral(0), 123);
            assert_eq!(reserve_0.data.b_supply, starting_b_supply_0 + 123);
            assert_eq!(user.has_collateral(), true);

            user.add_collateral(&e, &mut reserve_1, 456);
            assert_eq!(user.get_collateral(0), 123);
            assert_eq!(user.get_collateral(1), 456);
            assert_eq!(reserve_1.data.b_supply, starting_b_supply_1 + 456);
            assert_eq!(user.has_collateral(), true);

            user.remove_collateral(&e, &mut reserve_1, 100);
            assert_eq!(user.get_collateral(1), 356);
            assert_eq!(reserve_1.data.b_supply, starting_b_supply_1 + 356);
            assert_eq!(user.has_collateral(), true);

            user.remove_collateral(&e, &mut reserve_1, 356);
            assert_eq!(user.get_collateral(1), 0);
            assert_eq!(user.positions.collateral.len(), 1);
            assert_eq!(reserve_1.data.b_supply, starting_b_supply_1);
            assert_eq!(user.has_collateral(), true);

            user.remove_collateral(&e, &mut reserve_0, 123);
            assert_eq!(user.get_collateral(0), 0);
            assert_eq!(user.positions.collateral.len(), 0);
            assert_eq!(reserve_0.data.b_supply, starting_b_supply_0);
            assert_eq!(user.has_collateral(), false);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1216)")]
    fn test_add_collateral_zero_mint() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_collateral(0), 0);

            user.add_collateral(&e, &mut reserve_0, 0);
        });
    }

    #[test]
    fn test_add_collateral_accrues_emissions() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 10001000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_b_token_supply = reserve_0.data.b_supply;

        let emis_res_data = ReserveEmissionData {
            expiration: 20000000,
            eps: 0_10000000000000,
            index: 10000000000,
            last_time: 10000000, // 1000s elapsed
        };
        let emis_user_data = UserEmissionData {
            index: 9000000000,
            accrued: 0,
        };

        let mut user = User {
            address: samwise.clone(),
            positions: Positions {
                liabilities: map![&e],
                collateral: map![&e, (reserve_0.config.index, 700)],
                supply: map![&e, (reserve_0.config.index, 300)],
            },
        };
        e.as_contract(&pool, || {
            let res_0_d_token_index = reserve_0.config.index * 2 + 1;
            storage::set_res_emis_data(&e, &res_0_d_token_index, &emis_res_data);
            storage::set_user_emissions(&e, &samwise, &res_0_d_token_index, &emis_user_data);

            user.add_collateral(&e, &mut reserve_0, 123);
            assert_eq!(user.get_collateral(0), 823);
            assert_eq!(reserve_0.data.b_supply, starting_b_token_supply + 123);

            let new_emis_res_data = storage::get_res_emis_data(&e, &res_0_d_token_index).unwrap();
            let new_index = 10000000000
                + (1000i128 * 0_1000000).fixed_div_floor(
                    &e,
                    &starting_b_token_supply,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(new_emis_res_data.last_time, 10001000);
            assert_eq!(new_emis_res_data.index, new_index);
            let user_emis_data =
                storage::get_user_emissions(&e, &samwise, &res_0_d_token_index).unwrap();
            let new_accrual = 0
                + (new_index - emis_user_data.index).fixed_mul_floor(
                    &e,
                    &1000,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(user_emis_data.accrued, new_accrual);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1217)")]
    fn test_remove_collateral_zero_burn() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_collateral(0), 0);

            user.add_collateral(&e, &mut reserve_0, 123);
            assert_eq!(user.get_collateral(0), 123);

            user.remove_collateral(&e, &mut reserve_0, 0);
        });
    }

    #[test]
    fn test_remove_collateral_accrues_emissions() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 10001000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_b_token_supply = reserve_0.data.b_supply;

        let emis_res_data = ReserveEmissionData {
            expiration: 20000000,
            eps: 0_10000000000000,
            index: 10000000000,
            last_time: 10000000, // 1000s elapsed
        };
        let emis_user_data = UserEmissionData {
            index: 9000000000,
            accrued: 0,
        };

        let mut user = User {
            address: samwise.clone(),
            positions: Positions {
                liabilities: map![&e],
                collateral: map![&e, (reserve_0.config.index, 700)],
                supply: map![&e, (reserve_0.config.index, 300)],
            },
        };
        e.as_contract(&pool, || {
            let res_0_d_token_index = reserve_0.config.index * 2 + 1;
            storage::set_res_emis_data(&e, &res_0_d_token_index, &emis_res_data);
            storage::set_user_emissions(&e, &samwise, &res_0_d_token_index, &emis_user_data);

            user.remove_collateral(&e, &mut reserve_0, 123);
            assert_eq!(user.get_collateral(0), 577);
            assert_eq!(reserve_0.data.b_supply, starting_b_token_supply - 123);

            let new_emis_res_data = storage::get_res_emis_data(&e, &res_0_d_token_index).unwrap();
            let new_index = 10000000000
                + (1000i128 * 0_1000000).fixed_div_floor(
                    &e,
                    &starting_b_token_supply,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(new_emis_res_data.last_time, 10001000);
            assert_eq!(new_emis_res_data.index, new_index);
            let user_emis_data =
                storage::get_user_emissions(&e, &samwise, &res_0_d_token_index).unwrap();
            let new_accrual = 0
                + (new_index - emis_user_data.index).fixed_mul_floor(
                    &e,
                    &1000,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(user_emis_data.accrued, new_accrual);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #8)")]
    fn test_remove_collateral_over_balance_panics() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            user.add_collateral(&e, &mut reserve_0, 123);
            assert_eq!(user.get_collateral(0), 123);

            user.remove_collateral(&e, &mut reserve_0, 124);
        });
    }

    #[test]
    fn test_supply() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_b_supply_0 = reserve_0.data.b_supply;

        let mut reserve_1 = testutils::default_reserve(&e);
        reserve_1.config.index = 1;
        let starting_b_supply_1 = reserve_1.data.b_supply;

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_supply(0), 0);

            user.add_supply(&e, &mut reserve_0, 123);
            assert_eq!(user.get_supply(0), 123);
            assert_eq!(reserve_0.data.b_supply, starting_b_supply_0 + 123);

            user.add_supply(&e, &mut reserve_1, 456);
            assert_eq!(user.get_supply(0), 123);
            assert_eq!(user.get_supply(1), 456);
            assert_eq!(reserve_1.data.b_supply, starting_b_supply_1 + 456);

            user.remove_supply(&e, &mut reserve_1, 100);
            assert_eq!(user.get_supply(1), 356);
            assert_eq!(reserve_1.data.b_supply, starting_b_supply_1 + 356);

            user.remove_supply(&e, &mut reserve_1, 356);
            assert_eq!(user.get_supply(2), 0);
            assert_eq!(user.positions.supply.len(), 1);
            assert_eq!(reserve_1.data.b_supply, starting_b_supply_1);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1216)")]
    fn test_add_supply_zero_mint() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_supply(0), 0);

            user.add_supply(&e, &mut reserve_0, 0);
        });
    }

    #[test]
    fn test_add_supply_accrues_emissions() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 10001000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_b_token_supply = reserve_0.data.b_supply;

        let emis_res_data = ReserveEmissionData {
            expiration: 20000000,
            eps: 0_10000000000000,
            index: 10000000000,
            last_time: 10000000, // 1000s elapsed
        };
        let emis_user_data = UserEmissionData {
            index: 9000000000,
            accrued: 0,
        };

        let mut user = User {
            address: samwise.clone(),
            positions: Positions {
                liabilities: map![&e],
                collateral: map![&e, (reserve_0.config.index, 700)],
                supply: map![&e, (reserve_0.config.index, 300)],
            },
        };
        e.as_contract(&pool, || {
            let res_0_d_token_index = reserve_0.config.index * 2 + 1;
            storage::set_res_emis_data(&e, &res_0_d_token_index, &emis_res_data);
            storage::set_user_emissions(&e, &samwise, &res_0_d_token_index, &emis_user_data);

            user.add_supply(&e, &mut reserve_0, 123);
            assert_eq!(user.get_supply(0), 423);
            assert_eq!(reserve_0.data.b_supply, starting_b_token_supply + 123);

            let new_emis_res_data = storage::get_res_emis_data(&e, &res_0_d_token_index).unwrap();
            let new_index = 10000000000
                + (1000i128 * 0_1000000).fixed_div_floor(
                    &e,
                    &starting_b_token_supply,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(new_emis_res_data.last_time, 10001000);
            assert_eq!(new_emis_res_data.index, new_index);
            let user_emis_data =
                storage::get_user_emissions(&e, &samwise, &res_0_d_token_index).unwrap();
            let new_accrual = 0
                + (new_index - emis_user_data.index).fixed_mul_floor(
                    &e,
                    &1000,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(user_emis_data.accrued, new_accrual);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1217)")]
    fn test_remove_supply_zero_burn() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            assert_eq!(user.get_supply(0), 0);

            user.add_supply(&e, &mut reserve_0, 123);
            assert_eq!(user.get_supply(0), 123);

            user.remove_supply(&e, &mut reserve_0, 0);
        });
    }

    #[test]
    fn test_remove_supply_accrues_emissions() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 10001000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let mut reserve_0 = testutils::default_reserve(&e);
        let starting_b_token_supply = reserve_0.data.b_supply;

        let emis_res_data = ReserveEmissionData {
            expiration: 20000000,
            eps: 0_10000000000000,
            index: 10000000000,
            last_time: 10000000, // 1000s elapsed
        };
        let emis_user_data = UserEmissionData {
            index: 9000000000,
            accrued: 0,
        };

        let mut user = User {
            address: samwise.clone(),
            positions: Positions {
                liabilities: map![&e],
                collateral: map![&e, (reserve_0.config.index, 700)],
                supply: map![&e, (reserve_0.config.index, 300)],
            },
        };
        e.as_contract(&pool, || {
            let res_0_d_token_index = reserve_0.config.index * 2 + 1;
            storage::set_res_emis_data(&e, &res_0_d_token_index, &emis_res_data);
            storage::set_user_emissions(&e, &samwise, &res_0_d_token_index, &emis_user_data);

            user.remove_supply(&e, &mut reserve_0, 123);
            assert_eq!(user.get_supply(0), 177);
            assert_eq!(reserve_0.data.b_supply, starting_b_token_supply - 123);

            let new_emis_res_data = storage::get_res_emis_data(&e, &res_0_d_token_index).unwrap();
            let new_index = 10000000000
                + (1000i128 * 0_1000000).fixed_div_floor(
                    &e,
                    &starting_b_token_supply,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(new_emis_res_data.last_time, 10001000);
            assert_eq!(new_emis_res_data.index, new_index);
            let user_emis_data =
                storage::get_user_emissions(&e, &samwise, &res_0_d_token_index).unwrap();
            let new_accrual = 0
                + (new_index - emis_user_data.index).fixed_mul_floor(
                    &e,
                    &1000,
                    &(SCALAR_7 * SCALAR_7),
                );
            assert_eq!(user_emis_data.accrued, new_accrual);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #8)")]
    fn test_remove_supply_over_balance_panics() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            user.add_supply(&e, &mut reserve_0, 123);
            assert_eq!(user.get_supply(0), 123);

            user.remove_supply(&e, &mut reserve_0, 124);
        });
    }

    #[test]
    fn test_total_supply() {
        let e = Env::default();
        e.mock_all_auths();
        let samwise = Address::generate(&e);
        let pool = testutils::create_pool(&e);

        let mut reserve_0 = testutils::default_reserve(&e);

        let mut reserve_1 = testutils::default_reserve(&e);
        reserve_1.config.index = 1;

        let mut user = User {
            address: samwise.clone(),
            positions: Positions::env_default(&e),
        };
        e.as_contract(&pool, || {
            user.add_supply(&e, &mut reserve_0, 123);
            user.add_supply(&e, &mut reserve_1, 456);
            user.add_collateral(&e, &mut reserve_1, 789);
            assert_eq!(user.get_total_supply(0), 123);
            assert_eq!(user.get_total_supply(1), 456 + 789);
        });
    }
}
