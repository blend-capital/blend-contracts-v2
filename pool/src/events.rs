use soroban_sdk::{Address, Env, Symbol, Vec};

use crate::{AuctionData, ReserveConfig};

pub struct PoolEvents {}

impl PoolEvents {
    /// Emitted when a new admin is set for a pool
    ///
    /// - topics - `["set_admin", admin: Address]`
    /// - data - `new_admin: Address`
    ///
    /// ### Arguments
    /// * admin - The current admin of the pool
    /// * new_admin - The new admin of the pool
    pub fn set_admin(e: &Env, admin: Address, new_admin: Address) {
        let topics = (Symbol::new(&e, "set_admin"), admin);
        e.events().publish(topics, new_admin);
    }

    /// Emitted when pool parameters are updated
    ///
    /// - topics - `["update_pool", admin: Address]`
    /// - data - `[backstop_take_rate: u32, max_positions: u32]`
    ///
    /// ### Arguments
    /// * admin - The current admin of the pool
    /// * backstop_take_rate - The new backstop take rate
    /// * max_positions - The new maximum number of positions
    pub fn update_pool(e: &Env, admin: Address, backstop_take_rate: u32, max_positions: u32) {
        let topics = (Symbol::new(&e, "update_pool"), admin);
        e.events()
            .publish(topics, (backstop_take_rate, max_positions));
    }

    /// Emitted when a new reserve configuration change is queued
    ///
    /// - topics - `["queue_set_reserve", admin: Address]`
    /// - data - `[asset: Address, metadata: ReserveMetadata]`
    ///
    /// ### Arguments
    /// * admin - The current admin of the pool
    /// * asset - The asset to change the reserve configuration of
    /// * metadata - The new reserve configuration
    pub fn queue_set_reserve(e: &Env, admin: Address, asset: Address, metadata: ReserveConfig) {
        let topics = (Symbol::new(&e, "queue_set_reserve"), admin);
        e.events().publish(topics, (asset, metadata));
    }

    /// Emitted when a queued reserve configuration change is cancelled
    ///
    /// - topics - `["cancel_set_reserve", admin: Address]`
    /// - data - `asset: Address`
    ///
    /// ### Arguments
    /// * admin - The current admin of the pool
    /// * asset - The asset to cancel the reserve configuration change of
    pub fn cancel_set_reserve(e: &Env, admin: Address, asset: Address) {
        let topics = (Symbol::new(&e, "cancel_set_reserve"), admin);
        e.events().publish(topics, asset);
    }

    /// Emitted when a reserve configuration change is set
    ///
    /// - topics - `["set_reserve"]`
    /// - data - `[asset: Address, index: u32]`
    ///
    /// ### Arguments
    /// * asset - The asset to change the reserve configuration of
    /// * index - The reserve index
    pub fn set_reserve(e: &Env, asset: Address, index: u32) {
        let topics = (Symbol::new(&e, "set_reserve"),);
        e.events().publish(topics, (asset, index));
    }

    /// Emitted when pool status is updated (non-admin)
    ///
    /// - topics - `["set_status"]`
    /// - data - `new_status: PoolStatus`
    ///
    /// ### Arguments
    /// * new_status - The new pool status
    pub fn set_status(e: &Env, new_status: u32) {
        let topics = (Symbol::new(&e, "set_status"),);
        e.events().publish(topics, new_status);
    }

    /// Emitted when pool status is updated by admin
    ///
    /// - topics - `["set_status", admin: Address]`
    /// - data - `pool_status: PoolStatus`
    ///
    /// ### Arguments
    /// * admin - The admin setting the pool status
    /// * pool_status - The new pool status
    pub fn set_status_admin(e: &Env, admin: Address, pool_status: u32) {
        let topics = (Symbol::new(&e, "set_status"), admin);
        e.events().publish(topics, pool_status);
    }

    /// Emitted when reserve emissions are updated
    ///
    /// - topics - `["reserve_emission_update"]`
    /// - data - `[res_token_id: u32, eps: u64, expiration: u64]`
    ///
    /// ### Arguments
    /// * res_token_id - The reserve token ID
    /// * eps - The new emissions per second
    /// * expiration - The new expiration time
    pub fn reserve_emission_update(e: &Env, res_token_id: u32, eps: u64, expiration: u64) {
        let topics = (Symbol::new(e, "reserve_emission_update"),);
        e.events().publish(topics, (res_token_id, eps, expiration));
    }

    /// Emitted when emissions are gulped
    ///
    /// - topics - `["update_emissions"]`
    /// - data - `emissions: i128`
    ///
    /// ### Arguments
    /// * emissions - The amount of emissions gulped
    pub fn gulp_emissions(e: &Env, emissions: i128) {
        let topics = (Symbol::new(&e, "gulp_emissions"),);
        e.events().publish(topics, emissions);
    }

    /// Emitted when emissions are claimed
    ///
    /// - topics - `["claim", from: Address]`
    /// - data - `[reserve_token_ids: Vec<u32>, amount_claimed: i128]`
    ///
    /// ### Arguments
    /// * from - The address claiming the emissions
    /// * reserve_token_ids - The reserve token IDs claimed
    /// * amount_claimed - The amount claimed
    pub fn claim(e: &Env, from: Address, reserve_token_ids: Vec<u32>, amount_claimed: i128) {
        let topics = (Symbol::new(&e, "claim"), from);
        e.events()
            .publish(topics, (reserve_token_ids, amount_claimed));
    }

    /// Emitted when bad debt is recorded
    ///
    /// - topics - `["bad_debt", user: Address, asset: Address]`
    /// - data - `[d_tokens: i128]`
    ///
    /// ### Arguments
    /// * user - The user with bad debt
    /// * asset - The asset with bad debt
    /// * d_tokens - The amount of bad debt
    pub fn bad_debt(e: &Env, user: Address, asset: Address, d_tokens: i128) {
        let topics = (Symbol::new(e, "bad_debt"), user, asset);
        e.events().publish(topics, d_tokens);
    }

    /// Emitted when bad debt is defaulted
    ///
    /// - topics - `["defaulted_debt", asset: Address]`
    /// - data - `[d_tokens_burnt: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset with defaulted debt
    /// * d_tokens_burnt - The amount of defaulted d_tokens
    pub fn defaulted_debt(e: &Env, asset: Address, d_tokens_burnt: i128) {
        let topics = (Symbol::new(e, "defaulted_debt"), asset);
        e.events().publish(topics, d_tokens_burnt);
    }

    /// Emitted when tokens are supplied
    ///
    /// - topics - `["supply", asset: Address, from: Address]`
    /// - data - `[tokens_in: i128, b_tokens_minted: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset
    /// * from - The address whose position is being modified
    /// * tokens_in - The amount of tokens sent to the pool
    /// * b_tokens_minted - The amount of b_tokens minted
    pub fn supply(e: &Env, asset: Address, from: Address, tokens_in: i128, b_tokens_minted: i128) {
        let topics = (Symbol::new(e, "supply"), asset, from);
        e.events().publish(topics, (tokens_in, b_tokens_minted));
    }

    /// Emitted when tokens are withdrawn
    ///
    /// - topics - `["withdraw", asset: Address, from: Address]`
    /// - data - `[tokens_out: i128, b_tokens_burnt: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset
    /// * from - The address whose position is being modified
    /// * tokens_out - The amount of tokens withdrawn from the pool
    /// * b_tokens_burnt - The amount of b_tokens burnt
    pub fn withdraw(
        e: &Env,
        asset: Address,
        from: Address,
        tokens_out: i128,
        b_tokens_burnt: i128,
    ) {
        let topics = (Symbol::new(e, "withdraw"), asset, from);
        e.events().publish(topics, (tokens_out, b_tokens_burnt));
    }

    /// Emitted when collateral is supplied
    ///
    /// - topics - `["supply_collateral", asset: Address, from: Address]`
    /// - data - `[tokens_in: i128, b_tokens_minted: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset
    /// * from - The address whose position is being modified
    /// * tokens_in - The amount of tokens sent to the pool
    /// * b_tokens_minted - The amount of b_tokens minted
    pub fn supply_collateral(
        e: &Env,
        asset: Address,
        from: Address,
        tokens_in: i128,
        b_tokens_minted: i128,
    ) {
        let topics = (Symbol::new(e, "supply_collateral"), asset, from);
        e.events().publish(topics, (tokens_in, b_tokens_minted));
    }

    /// Emitted when collateral is withdrawn
    ///
    /// - topics - `["withdraw_collateral", asset: Address, from: Address]`
    /// - data - `[tokens_out: i128, b_tokens_burnt: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset
    /// * from - The address whose position is being modified
    /// * tokens_out - The amount of tokens withdrawn from the pool
    /// * b_tokens_burnt - The amount of b_tokens burnt
    pub fn withdraw_collateral(
        e: &Env,
        asset: Address,
        from: Address,
        tokens_out: i128,
        b_tokens_burnt: i128,
    ) {
        let topics = (Symbol::new(e, "withdraw_collateral"), asset, from);
        e.events().publish(topics, (tokens_out, b_tokens_burnt));
    }

    /// Emitted when tokens are borrowed
    ///
    /// - topics - `["borrow", asset: Address, from: Address]`
    /// - data - `[tokens_out: i128, d_tokens_minted: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset
    /// * from - The address whose position is being modified
    /// * tokens_out - The amount of tokens sent from the pool
    /// * d_tokens_burnt - The amount of d_tokens burnt
    pub fn borrow(e: &Env, asset: Address, from: Address, tokens_out: i128, d_tokens_minted: i128) {
        let topics = (Symbol::new(e, "borrow"), asset, from);
        e.events().publish(topics, (tokens_out, d_tokens_minted));
    }

    /// Emitted when a loan is repaid
    ///
    /// - topics - `["repay", asset: Address, from: Address]`
    /// - data - `[tokens_in: i128, d_tokens_burnt: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset
    /// * from - The address whose position is being modified
    /// * tokens_in - The amount of tokens sent to the pool
    /// * d_tokens_burnt - The amount of d_tokens burnt
    pub fn repay(e: &Env, asset: Address, from: Address, tokens_in: i128, d_tokens_burnt: i128) {
        let topics = (Symbol::new(e, "repay"), asset, from);
        e.events().publish(topics, (tokens_in, d_tokens_burnt));
    }

    /// Emitted when a reserve updates its bToken rate
    ///
    /// - topics - `["gulp", asset: Address]`
    /// - data - `[token_delta: i128, new_b_rate: i128]`
    ///
    /// ### Arguments
    /// * asset - The asset
    /// * token_delta - The change in token balance
    /// * new_b_rate - The new b rate
    pub fn gulp(e: &Env, asset: Address, token_delta: i128, new_b_rate: i128) {
        let topics = (Symbol::new(e, "gulp"), asset);
        e.events().publish(topics, (token_delta, new_b_rate));
    }

    /// Emitted when a new auction is created
    ///
    /// - topics - `["new_auction", user: Address, auction_type: u32]`
    /// - data - `[percent: u32, auction_data: AuctionData]`
    ///
    /// ### Arguments
    /// * auction_type - The type of auction
    /// * user - The auction user
    /// * percent - The percent of assets auctioned off
    /// * auction_data - The auction data
    pub fn new_auction(
        e: &Env,
        auction_type: u32,
        user: Address,
        percent: u32,
        auction_data: AuctionData,
    ) {
        let topics = (Symbol::new(e, "new_auction"), auction_type, user);
        e.events().publish(topics, (percent, auction_data));
    }

    /// Emitted when an auction is filled
    ///
    /// - topics - `["fill_auction", user: Address, auction_type: u32]`
    /// - data - `[filler: Address, fill_percent: i128, filled_auction_data: AuctionData]`
    ///
    /// ### Arguments
    /// * auction_type - The type of auction
    /// * user - The auction user
    /// * filler - The address of the filler
    /// * fill_percent - The percentage of the auction filled
    /// * filled_auction_data - The filled auction data
    pub fn fill_auction(
        e: &Env,
        auction_type: u32,
        user: Address,
        filler: Address,
        fill_percent: i128,
        filled_auction_data: AuctionData,
    ) {
        let topics = (Symbol::new(e, "fill_auction"), auction_type, user);
        e.events()
            .publish(topics, (filler, fill_percent, filled_auction_data));
    }

    /// Emitted when a liquidation auction is deleted
    ///
    /// - topics - `["delete_liquidation_auction", from: Address]`
    /// - data - `()`
    ///
    /// ### Arguments
    /// * from - The address of the liquidated user
    pub fn delete_liquidation_auction(e: &Env, from: Address) {
        let topics = (Symbol::new(&e, "delete_liquidation_auction"), from);
        e.events().publish(topics, ());
    }
}
