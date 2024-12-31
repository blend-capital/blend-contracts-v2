use soroban_sdk::{Address, Env, Symbol};

pub struct BackstopEvents {}

impl BackstopEvents {
    /// Emitted when tokens are deposited into a backstop
    ///
    /// - topics - `["deposit", pool_address: Address, from: Address]`
    /// - data - `[tokens_in: i128, backstop_shares_minted: i128]`
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    /// * `from` - The address of the user depositing tokens
    /// * `tokens_in` - The amount of tokens sent to the backstop
    /// * `backstop_shares_minted` - The amount of backstop shares minted
    pub fn deposit(
        e: &Env,
        pool_address: Address,
        from: Address,
        tokens_in: i128,
        backstop_shares_minted: i128,
    ) {
        let topics = (Symbol::new(e, "deposit"), pool_address, from);
        e.events()
            .publish(topics, (tokens_in, backstop_shares_minted));
    }

    /// Emitted when a withdrawal is queued
    ///
    /// - topics - `["queue_withdrawal", pool_address: Address, from: Address]`
    /// - data - `[amount: i128, expiration: u64]`
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    /// * `from` - The address of the user queuing the withdrawal
    /// * `amount` - The amount of shares being queued for withdrawal
    /// * `expiration` - The expiration timestamp of the withdrawal request
    pub fn queue_withdrawal(
        e: &Env,
        pool_address: Address,
        from: Address,
        amount: i128,
        expiration: u64,
    ) {
        let topics = (Symbol::new(e, "queue_withdrawal"), pool_address, from);
        e.events().publish(topics, (amount, expiration));
    }

    /// Emitted when a withdrawal is dequeued
    ///
    /// - topics - `["dequeue_withdrawal", pool_address: Address, from: Address]`
    /// - data - `[amount: i128]`
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    /// * `from` - The address of the user dequeuing the withdrawal
    /// * `amount` - The amount of shares being dequeued
    pub fn dequeue_withdrawal(e: &Env, pool_address: Address, from: Address, amount: i128) {
        let topics = (Symbol::new(e, "dequeue_withdrawal"), pool_address, from);
        e.events().publish(topics, amount);
    }

    /// Emitted when tokens are withdrawn from the backstop
    ///
    /// - topics - `["withdraw", pool_address: Address, from: Address]`
    /// - data - `[amount: i128, tokens_out: i128]`
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    /// * `from` - The address of the user withdrawing tokens
    /// * `amount` - The amount of backstop shares being burned
    /// * `tokens_out` - The amount of tokens being withdrawn
    pub fn withdraw(e: &Env, pool_address: Address, from: Address, amount: i128, tokens_out: i128) {
        let topics = (Symbol::new(e, "withdraw"), pool_address, from);
        e.events().publish(topics, (amount, tokens_out));
    }

    /// Emitted when new emissions are prepared
    /// - topics - `["distribute"]`
    /// - data - `[new_tokens_emitted: i128]`
    ///
    /// ### Arguments
    /// * `new_tokens_emitted` - The amount of new tokens emitted
    pub fn distribute(e: &Env, new_tokens_emitted: i128) {
        let topics = (Symbol::new(e, "distribute"),);
        e.events().publish(topics, new_tokens_emitted);
    }

    /// Emitted when new emissions are gulped
    ///
    /// - topics - `["gulp_emissions"]`
    /// - data - `[new_tokens_emitted: i128]`
    ///
    /// ### Arguments
    /// * `new_tokens_emitted` - The amount of new tokens emitted
    pub fn gulp_emissions(e: &Env, new_tokens_emitted: i128) {
        let topics = (Symbol::new(e, "gulp_emissions"),);
        e.events().publish(topics, new_tokens_emitted);
    }

    /// Emitted when the reward zone is updated
    ///
    /// - topics - `["rw_zone"]`
    /// - data - `[to_add: Address, to_remove: Address]`
    ///
    /// ### Arguments
    /// * `to_add` - The address to add to the reward zone
    /// * `to_remove` - The address to remove from the reward zone
    pub fn rw_zone(e: &Env, to_add: Address, to_remove: Address) {
        let topics = (Symbol::new(e, "rw_zone"),);
        e.events().publish(topics, (to_add, to_remove));
    }

    /// Emitted when emissions are claimed
    ///
    /// - topics - `["claim", from: Address]`
    /// - data - `[amount: i128]`
    ///
    /// ### Arguments
    /// * `from` - The address of the user claiming emissions
    /// * `amount` - The amount of emissions claimed
    pub fn claim(e: &Env, from: Address, amount: i128) {
        let topics = (Symbol::new(e, "claim"), from);
        e.events().publish(topics, amount);
    }

    /// Emitted when tokens are drawn from the backstop
    ///
    /// - topics - `["draw", pool_address: Address]`
    /// - data - `[to: Address, amount: i128]`
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    /// * `to` - The address receiving the drawn tokens
    /// * `amount` - The amount of tokens drawn
    pub fn draw(e: &Env, pool_address: Address, to: Address, amount: i128) {
        let topics = (Symbol::new(e, "draw"), pool_address);
        e.events().publish(topics, (to, amount));
    }

    /// Emitted when tokens are donated to the backstop
    ///
    /// - topics - `["donate", pool_address: Address, from: Address]`
    /// - data - `[amount: i128]`
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    /// * `from` - The address of the donor
    /// * `amount` - The amount of tokens donated
    pub fn donate(e: &Env, pool_address: Address, from: Address, amount: i128) {
        let topics = (Symbol::new(e, "donate"), pool_address, from);
        e.events().publish(topics, amount);
    }
}
