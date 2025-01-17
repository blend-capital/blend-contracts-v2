use crate::{
    backstop::{self, load_pool_backstop_data, PoolBackstopData, UserBalance, Q4W},
    constants::{MAX_BACKFILLED_EMISSIONS, SCALAR_7},
    dependencies::EmitterClient,
    emissions,
    errors::BackstopError,
    events::BackstopEvents,
    storage,
};
use soroban_sdk::{contract, contractclient, contractimpl, panic_with_error, Address, Env, Vec};

/// ### Backstop
///
/// A backstop module for the Blend protocol's Isolated Lending Pools
#[contract]
pub struct BackstopContract;

#[contractclient(name = "BackstopClient")]
pub trait Backstop {
    /********** Core **********/

    /// Deposit backstop tokens from "from" into the backstop of a pool
    ///
    /// Returns the number of backstop pool shares minted
    ///
    /// ### Arguments
    /// * `from` - The address depositing into the backstop
    /// * `pool_address` - The address of the pool
    /// * `amount` - The amount of tokens to deposit
    fn deposit(e: Env, from: Address, pool_address: Address, amount: i128) -> i128;

    /// Queue deposited pool shares from "from" for withdraw from a backstop of a pool
    ///
    /// Returns the created queue for withdrawal
    ///
    /// ### Arguments
    /// * `from` - The address whose deposits are being queued for withdrawal
    /// * `pool_address` - The address of the pool
    /// * `amount` - The amount of shares to queue for withdraw
    fn queue_withdrawal(e: Env, from: Address, pool_address: Address, amount: i128) -> Q4W;

    /// Dequeue a currently queued pool share withdraw for "form" from the backstop of a pool
    ///
    /// ### Arguments
    /// * `from` - The address whose deposits are being queued for withdrawal
    /// * `pool_address` - The address of the pool
    /// * `amount` - The amount of shares to dequeue
    fn dequeue_withdrawal(e: Env, from: Address, pool_address: Address, amount: i128);

    /// Withdraw shares from "from"s withdraw queue for a backstop of a pool
    ///
    /// Returns the amount of tokens returned
    ///
    /// ### Arguments
    /// * `from` - The address whose shares are being withdrawn
    /// * `pool_address` - The address of the pool
    /// * `amount` - The amount of shares to withdraw
    fn withdraw(e: Env, from: Address, pool_address: Address, amount: i128) -> i128;

    /// Fetch the balance of backstop shares of a pool for the user
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    /// * `user` - The user to fetch the balance for
    fn user_balance(e: Env, pool: Address, user: Address) -> UserBalance;

    /// Fetch the backstop data for the pool
    ///
    /// Return a summary of the pool's backstop data
    ///
    /// ### Arguments
    /// * `pool_address` - The address of the pool
    fn pool_data(e: Env, pool: Address) -> PoolBackstopData;

    /// Fetch the backstop token for the backstop
    fn backstop_token(e: Env) -> Address;

    /********** Emissions **********/

    /// Update the backstop with new emissions for all reward zone pools
    ///
    /// Returns the amount of new emissions for all reward zone pools
    fn distribute(e: Env) -> i128;

    /// Distribute emissions to a reward zone pool and its backstop
    ///
    /// Returns the amount of BLND emissions distributed to the pool
    ///
    /// ### Arguments
    /// * `pool` - The address of the pool to distribute emissions to
    ///
    /// ### Errors
    /// If the pool is not in the reward zone or the pool does not authorize the call
    fn gulp_emissions(e: Env, pool: Address) -> i128;

    /// Add a pool to the reward zone, and if the reward zone is full, a pool to remove
    ///
    /// ### Arguments
    /// * `to_add` - The address of the pool to add
    /// * `to_remove` - The address of the pool to remove (Optional - Used if the reward zone is full)
    ///
    /// ### Errors
    /// If the pool to remove has more tokens, or if distribution occurred in the last 48 hours
    fn add_reward(e: Env, to_add: Address, to_remove: Option<Address>);

    /// Remove a pool from the reward zone
    ///
    /// ### Arguments
    /// * `to_remove` - The address of the pool to remove
    ///
    /// ### Errors
    /// If the pool is not below the threshold or if the pool is not in the reward zone
    fn remove_reward(e: Env, to_remove: Address);

    /// Claim backstop deposit emissions from a list of pools for `from`
    ///
    /// Returns the amount of BLND emissions claimed
    ///
    /// ### Arguments
    /// * `from` - The address of the user claiming emissions
    /// * `pool_addresses` - The Vec of addresses to claim backstop deposit emissions from
    /// * `to` - The Address to send to emissions to
    ///
    /// ### Errors
    /// If an invalid pool address is included
    fn claim(e: Env, from: Address, pool_addresses: Vec<Address>, to: Address) -> i128;

    /// Drop initial BLND to a list of addresses through the emitter
    fn drop(e: Env);

    /********** Fund Management *********/

    /// (Only Pool) Take backstop token from a pools backstop
    ///
    /// ### Arguments
    /// * `from` - The address of the pool drawing tokens from the backstop
    /// * `pool_address` - The address of the pool
    /// * `amount` - The amount of backstop tokens to draw
    /// * `to` - The address to send the backstop tokens to
    ///
    /// ### Errors
    /// If the pool does not have enough backstop tokens, or if the pool does
    /// not authorize the call
    fn draw(e: Env, pool_address: Address, amount: i128, to: Address);

    /// (Only Pool) Sends backstop tokens from "from" to a pools backstop
    ///
    /// NOTE: This is not a deposit, and "from" will permanently lose access to the funds
    ///
    /// ### Arguments
    /// * `from` - tge
    /// * `pool_address` - The address of the pool
    /// * `amount` - The amount of BLND to add
    ///
    /// ### Errors
    /// If the `pool_address` is not valid, backstop does not have sufficient allowance from `from`, or if the pool does not
    /// authorize the call
    fn donate(e: Env, from: Address, pool_address: Address, amount: i128);

    /// Updates the underlying value of 1 backstop token
    ///
    /// ### Returns
    /// A tuple of (blnd_per_tkn, usdc_per_tkn) of underlying value per backstop token
    ///
    /// ### Errors
    /// If the underlying value is unable to be computed
    fn update_tkn_val(e: Env) -> (i128, i128);
}

#[contractimpl]
impl BackstopContract {
    /// Construct the backstop contract
    ///
    /// ### Arguments
    /// * `backstop_token` - The backstop token ID - an LP token with the pair BLND:USDC
    /// * `emitter` - The Emitter contract ID
    /// * `blnd_token` - The BLND token ID
    /// * `usdc_token` - The USDC token ID
    /// * `pool_factory` - The pool factory ID
    /// * `drop_list` - The list of addresses to distribute initial BLND to and the percent of the distribution they should receive
    pub fn __constructor(
        e: Env,
        backstop_token: Address,
        emitter: Address,
        blnd_token: Address,
        usdc_token: Address,
        pool_factory: Address,
        drop_list: Vec<(Address, i128)>,
    ) {
        storage::set_backstop_token(&e, &backstop_token);
        storage::set_blnd_token(&e, &blnd_token);
        storage::set_usdc_token(&e, &usdc_token);
        storage::set_pool_factory(&e, &pool_factory);
        let mut drop_total: i128 = 0;
        for (_, amount) in drop_list.iter() {
            drop_total += amount;
        }
        if drop_total + MAX_BACKFILLED_EMISSIONS > 50_000_000 * SCALAR_7 {
            panic_with_error!(&e, BackstopError::BadRequest);
        }
        storage::set_drop_list(&e, &drop_list);
        storage::set_emitter(&e, &emitter);
    }
}

/// @dev
/// The contract implementation only manages the authorization / authentication required from the caller(s), and
/// utilizes other modules to carry out contract functionality.
#[contractimpl]
impl Backstop for BackstopContract {
    /********** Core **********/

    fn deposit(e: Env, from: Address, pool_address: Address, amount: i128) -> i128 {
        storage::extend_instance(&e);
        from.require_auth();

        let to_mint = backstop::execute_deposit(&e, &from, &pool_address, amount);

        BackstopEvents::deposit(&e, pool_address, from, amount, to_mint);
        to_mint
    }

    fn queue_withdrawal(e: Env, from: Address, pool_address: Address, amount: i128) -> Q4W {
        storage::extend_instance(&e);
        from.require_auth();

        let to_queue = backstop::execute_queue_withdrawal(&e, &from, &pool_address, amount);

        BackstopEvents::queue_withdrawal(&e, pool_address, from, amount, to_queue.exp);
        to_queue
    }

    fn dequeue_withdrawal(e: Env, from: Address, pool_address: Address, amount: i128) {
        storage::extend_instance(&e);
        from.require_auth();

        backstop::execute_dequeue_withdrawal(&e, &from, &pool_address, amount);

        BackstopEvents::dequeue_withdrawal(&e, pool_address, from, amount);
    }

    fn withdraw(e: Env, from: Address, pool_address: Address, amount: i128) -> i128 {
        storage::extend_instance(&e);
        from.require_auth();

        let to_withdraw = backstop::execute_withdraw(&e, &from, &pool_address, amount);

        BackstopEvents::withdraw(&e, pool_address, from, amount, to_withdraw);
        to_withdraw
    }

    fn user_balance(e: Env, pool: Address, user: Address) -> UserBalance {
        storage::get_user_balance(&e, &pool, &user)
    }

    fn pool_data(e: Env, pool: Address) -> PoolBackstopData {
        load_pool_backstop_data(&e, &pool)
    }

    fn backstop_token(e: Env) -> Address {
        storage::get_backstop_token(&e)
    }

    /********** Emissions **********/

    fn distribute(e: Env) -> i128 {
        storage::extend_instance(&e);
        let new_emissions = emissions::distribute(&e);

        BackstopEvents::distribute(&e, new_emissions);
        new_emissions
    }

    fn gulp_emissions(e: Env, pool: Address) -> i128 {
        storage::extend_instance(&e);
        pool.require_auth();
        let (backstop_emissions, pool_emissions) = emissions::gulp_emissions(&e, &pool);

        BackstopEvents::gulp_emissions(&e, pool, backstop_emissions, pool_emissions);
        pool_emissions
    }

    fn add_reward(e: Env, to_add: Address, to_remove: Option<Address>) {
        storage::extend_instance(&e);
        emissions::add_to_reward_zone(&e, to_add.clone(), to_remove.clone());

        BackstopEvents::rw_zone_add(&e, to_add, to_remove);
    }

    fn remove_reward(e: Env, to_remove: Address) {
        storage::extend_instance(&e);
        emissions::remove_from_reward_zone(&e, to_remove.clone());

        BackstopEvents::rw_zone_remove(&e, to_remove);
    }

    fn claim(e: Env, from: Address, pool_addresses: Vec<Address>, to: Address) -> i128 {
        storage::extend_instance(&e);
        from.require_auth();

        let amount = emissions::execute_claim(&e, &from, &pool_addresses, &to);

        BackstopEvents::claim(&e, from, amount);
        amount
    }

    fn drop(e: Env) {
        let mut drop_list = storage::get_drop_list(&e);
        let backfilled_emissions = storage::get_backfill_emissions(&e);
        drop_list.push_back((e.current_contract_address(), backfilled_emissions));
        let emitter_client = EmitterClient::new(&e, &storage::get_emitter(&e));
        emitter_client.drop(&drop_list)
    }

    /********** Fund Management *********/

    fn draw(e: Env, pool_address: Address, amount: i128, to: Address) {
        storage::extend_instance(&e);
        pool_address.require_auth();

        backstop::execute_draw(&e, &pool_address, amount, &to);

        BackstopEvents::draw(&e, pool_address, to, amount);
    }

    fn donate(e: Env, from: Address, pool_address: Address, amount: i128) {
        storage::extend_instance(&e);
        from.require_auth();
        pool_address.require_auth();

        backstop::execute_donate(&e, &from, &pool_address, amount);

        BackstopEvents::donate(&e, pool_address, from, amount);
    }

    fn update_tkn_val(e: Env) -> (i128, i128) {
        storage::extend_instance(&e);

        let backstop_token = storage::get_backstop_token(&e);
        let blnd_token = storage::get_blnd_token(&e);
        let usdc_token = storage::get_usdc_token(&e);

        backstop::execute_update_comet_token_value(&e, &backstop_token, &blnd_token, &usdc_token)
    }
}

/// Require that an incoming amount is not negative
///
/// ### Arguments
/// * `amount` - The amount
///
/// ### Errors
/// If the number is negative
pub fn require_nonnegative(e: &Env, amount: i128) {
    if amount.is_negative() {
        panic_with_error!(e, BackstopError::NegativeAmountError);
    }
}
