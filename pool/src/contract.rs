use crate::{
    auctions::{self, AuctionData},
    emissions::{self, ReserveEmissionMetadata},
    events::PoolEvents,
    pool::{self, FlashLoan, Positions, Request, Reserve},
    storage::{self, ReserveConfig},
    PoolConfig, PoolError, ReserveEmissionData, UserEmissionData,
};
use soroban_sdk::{
    contract, contractclient, contractimpl, panic_with_error, Address, Env, String, Vec,
};

/// ### Pool
///
/// An isolated money market pool.
#[contract]
pub struct PoolContract;

#[contractclient(name = "PoolClient")]
pub trait Pool {
    /// (Admin only) Set a new address to become the admin of the pool. This
    /// must be accepted by the new admin w/ `accept_admin` to take effect.
    ///
    /// ### Arguments
    /// * `new_admin` - The new admin address
    ///
    /// ### Panics
    /// If the caller is not the admin
    fn propose_admin(e: Env, new_admin: Address);

    /// (Proposed admin only) Accept the admin role. Ensures the new admin
    /// can safely submit transactions before taking over the pool admin role.
    ///
    /// ### Panics
    /// If the caller is not the proposed admin
    fn accept_admin(e: Env);

    /// (Admin only) Update the pool
    ///
    /// ### Arguments
    /// * `backstop_take_rate` - The new take rate for the backstop (7 decimals)
    /// * `max_positions` - The new maximum number of allowed positions for a single user's account
    /// * `min_collateral` - The new minimum collateral required to open a borrow position,
    ///                      in the oracles base asset decimals
    ///
    /// ### Panics
    /// If the caller is not the admin
    fn update_pool(e: Env, backstop_take_rate: u32, max_positions: u32, min_collateral: i128);

    /// (Admin only) Queues setting data for a reserve in the pool
    ///
    /// ### Arguments
    /// * `asset` - The underlying asset to add as a reserve
    /// * `config` - The ReserveConfig for the reserve
    ///   Includes `min_position`: the minimum underlying amount a nonzero collateral position
    ///   in this reserve must hold; 0 disables the check
    ///
    /// ### Panics
    /// If the caller is not the admin
    fn queue_set_reserve(e: Env, asset: Address, metadata: ReserveConfig);

    /// (Admin only) Cancels the queued set of a reserve in the pool
    ///
    /// ### Arguments
    /// * `asset` - The underlying asset to add as a reserve
    ///
    /// ### Panics
    /// If the caller is not the admin or the reserve is not queued for initialization
    fn cancel_set_reserve(e: Env, asset: Address);

    /// Executes the queued set of a reserve in the pool
    ///
    /// ### Arguments
    /// * `asset` - The underlying asset to add as a reserve
    ///
    /// ### Panics
    /// If the reserve is not queued for initialization
    /// or is already setup
    /// or has invalid metadata
    fn set_reserve(e: Env, asset: Address) -> u32;

    /// Fetch the pool configuration
    fn get_config(e: Env) -> PoolConfig;

    /// Fetch the admin address of the pool
    fn get_admin(e: Env) -> Address;

    /// Fetch the a vec addresses of all reserves in the pool. The index of the reserve
    /// in this vec defines the index of the reserve in the pool, used in places like `Positions`.
    fn get_reserve_list(e: Env) -> Vec<Address>;

    /// Fetch information about a reserve, updated to the current ledger
    ///
    /// ### Arguments
    /// * `asset` - The address of the reserve asset
    fn get_reserve(e: Env, asset: Address) -> Reserve;

    /// Fetch the positions for an address. For each position type, there is a map of the reserve index
    /// to the position for that reserve, if it exists.
    ///
    /// ### Arguments
    /// * `address` - The address to fetch positions for
    fn get_positions(e: Env, address: Address) -> Positions;

    /// Submit a set of requests to the pool where `from` takes on the position, `spender` sends any
    /// required tokens to the pool and `to` receives any tokens sent from the pool.
    ///
    /// Returns the new positions for `from`
    ///
    /// ### Arguments
    /// * `from` - The address of the user whose positions are being modified
    /// * `spender` - The address of the user who is sending tokens to the pool
    /// * `to` - The address of the user who is receiving tokens from the pool
    /// * `requests` - A vec of requests to be processed
    ///
    /// ### Panics
    /// If the request is not able to be completed for cases like insufficient funds or invalid health factor.
    /// Request types 7 and 8 (fill bad debt / interest auction) are unsupported and rejected before auction storage is read.
    fn submit(
        e: Env,
        from: Address,
        spender: Address,
        to: Address,
        requests: Vec<Request>,
    ) -> Positions;

    /// Submit a set of requests to the pool where `from` takes on the position, `spender` sends any
    /// required tokens to the pool using transfer_from and `to` receives any tokens sent from the pool.
    ///
    /// Returns the new positions for `from`
    ///
    /// ### Arguments
    /// * `from` - The address of the user whose positions are being modified
    /// * `spender` - The address of the user who is sending tokens to the pool
    /// * `to` - The address of the user who is receiving tokens from the pool
    /// * `requests` - A vec of requests to be processed
    ///
    /// ### Panics
    /// If the request is not able to be completed for cases like insufficient funds, insufficient allowance, or invalid health factor.
    /// Request types 7 and 8 (fill bad debt / interest auction) are unsupported and rejected.
    fn submit_with_allowance(
        e: Env,
        from: Address,
        spender: Address,
        to: Address,
        requests: Vec<Request>,
    ) -> Positions;

    /// Submit flash loan and a set of requests to the pool where `from` takes on the position. The flash loan will be invoked using
    /// the `flash_loan` arguments and `from` as the caller. For the requests, `from` sends any required tokens to the pool
    /// using transfer_from and receives any tokens sent from the pool.
    ///
    /// Returns the new positions for `from`
    ///
    /// ### Arguments
    /// * `from` - The address of the user whose positions are being modified and also the address of
    /// the user who is sending and receiving the tokens to the pool.
    /// * `flash_loan` - Arguments relative to the flash loan: receiver contract, asset and borroed amount.
    /// * `requests` - A vec of requests to be processed
    ///
    /// ### Panics
    /// If the request is not able to be completed for cases like insufficient funds ,insufficient allowance, or invalid health factor
    fn flash_loan(
        e: Env,
        from: Address,
        flash_loan: FlashLoan,
        requests: Vec<Request>,
    ) -> Positions;

    /// Update the pool status based on the backstop state - backstop triggered status' are odd numbers
    /// * 1 = backstop active - if the minimum backstop deposit has been reached
    ///                and 30% of backstop deposits are not queued for withdrawal
    ///                then all pool operations are permitted
    /// * 3 = backstop on-ice - if the minimum backstop deposit has not been reached
    ///                or 30% of backstop deposits are queued for withdrawal and admin active isn't set
    ///                or 50% of backstop deposits are queued for withdrawal
    ///                then borrowing and cancelling liquidations are not permitted
    /// * 5 = backstop frozen - if 60% of backstop deposits are queued for withdrawal and admin on-ice isn't set
    ///                or 75% of backstop deposits are queued for withdrawal
    ///                then all borrowing, cancelling liquidations, and supplying are not permitted
    ///
    /// ### Panics
    /// If the pool is currently on status 4, "admin-freeze", where only the admin
    /// can perform a status update via `set_status`
    fn update_status(e: Env) -> u32;

    /// (Admin only) Pool status is changed to `pool_status`
    /// * 0 = admin active - requires that the backstop threshold is met
    ///                 and less than 50% of backstop deposits are queued for withdrawal
    /// * 2 = admin on-ice - requires that less than 75% of backstop deposits are queued for withdrawal
    /// * 4 = admin frozen - can always be set. Status 4 is permanent: even the admin cannot move the pool out of it
    ///                 (re-setting 4 is allowed; any other status reverts with `StatusNotAllowed`)
    ///
    /// ### Arguments
    /// * `pool_status` - The pool status to be set
    ///
    /// ### Panics
    /// If the caller is not the admin
    /// If the specified conditions are not met for the status to be set
    fn set_status(e: Env, pool_status: u32);

    /// Settles pool-owned orphan supply shares for a reserve. This only succeeds once the reserve's debt is zero
    /// and always returns 0.
    ///
    /// This does NOT reconcile the pool's underlying token balance: direct token transfers to the pool and positive
    /// balance adjustments (e.g. rebases) are not credited to suppliers or the backstop (unrecoverable surplus
    /// policy). Negative token deltas are likewise ignored.
    ///
    /// ### Arguments
    /// * `asset` - The address of the asset to gulp
    ///
    /// Returns 0 (no tokens are gulped)
    ///
    /// ### Panics
    /// If the reserve still has debt, or b-token emissions state is contradictory (`BadRequest`)
    fn gulp(e: Env, asset: Address) -> i128;

    /********* Emission Functions **********/

    /// Consume emissions from the backstop and distribute to the reserves based
    /// on the reserve emission configuration.
    ///
    /// Returns amount of new tokens emitted
    fn gulp_emissions(e: Env) -> i128;

    /// (Admin only) Set the emission configuration for the pool
    ///
    /// Changes will be applied in the next pool `update_emissions`, and affect the next emission cycle
    ///
    /// ### Arguments
    /// * `res_emission_metadata` - A vector of ReserveEmissionMetadata to update metadata to
    ///
    /// ### Panics
    /// * If the caller is not the admin
    fn set_emissions_config(e: Env, res_emission_metadata: Vec<ReserveEmissionMetadata>);

    /// Claims outstanding emissions for the caller for the given reserve's.
    ///
    /// A reserve token id is a unique identifier for a position in a pool.
    /// - For a reserve's dTokens (liabilities), reserve_token_id = reserve_index * 2
    /// - For a reserve's bTokens (supply/collateral), reserve_token_id = reserve_index * 2 + 1
    ///
    /// Returns the number of tokens claimed
    ///
    /// ### Arguments
    /// * `from` - The address claiming
    /// * `reserve_token_ids` - Vector of reserve token ids
    /// * `to` - The Address to send the claimed tokens to
    fn claim(e: Env, from: Address, reserve_token_ids: Vec<u32>, to: Address) -> i128;

    /// Get the emissions data for a reserve token
    ///
    /// A reserve token id is a unique identifier for a position in a pool.
    /// - For a reserve's dTokens (liabilities), reserve_token_id = reserve_index * 2
    /// - For a reserve's bTokens (supply/collateral), reserve_token_id = reserve_index * 2 + 1
    ///
    /// ### Arguments
    /// * `reserve_token_id` - The reserve token id
    fn get_reserve_emissions(e: Env, reserve_token_id: u32) -> Option<ReserveEmissionData>;

    /// Get the emissions data for a user
    ///
    /// A reserve token id is a unique identifier for a position in a pool.
    /// - For a reserve's dTokens (liabilities), reserve_token_id = reserve_index * 2
    /// - For a reserve's bTokens (supply/collateral), reserve_token_id = reserve_index * 2 + 1
    ///
    /// ### Arguments
    /// * `user` - The address of the user
    /// * `reserve_token_id` - The reserve token id
    fn get_user_emissions(e: Env, user: Address, reserve_token_id: u32)
        -> Option<UserEmissionData>;

    /***** Auction / Liquidation Functions *****/

    /// Create a new auction. Only user liquidation auctions (type 0) are supported.
    ///
    /// ### Arguments
    /// * `auction_type` - The type of auction. Only 0 (UserLiquidation) is supported; types 1 (bad debt) and 2 (interest)
    ///                    are rejected with `BadRequest` before their constructors run.
    /// * `user` - The Address being liquidated. This is the source of the assets being auctioned.
    /// * `bid` - The set of assets to include in the auction bid, or what the filler spends when filling the auction.
    /// * `lot` - The set of assets to include in the auction lot, or what the filler receives when filling the auction.
    /// * `percent` - The percent of the assets to be auctioned off as a percentage (15 => 15%).
    fn new_auction(
        e: Env,
        auction_type: u32,
        user: Address,
        bid: Vec<Address>,
        lot: Vec<Address>,
        percent: u32,
    ) -> AuctionData;

    /// Fetch an auction from the ledger. Returns the base auction. On fill, this will be scaled based on the
    /// number of blocks that have passed since the auction was created.
    ///
    /// ### Arguments
    /// * `auction_type` - The type of auction. Only 0 (UserLiquidation) is supported; types 1 (bad debt) and 2 (interest)
    ///                    are rejected with `BadRequest`
    /// * `user` - The Address involved in the auction
    ///
    /// ### Panics
    /// If the auction does not exist
    fn get_auction(e: Env, auction_type: u32, user: Address) -> AuctionData;

    /// Delete a stale auction. A stale auction is one that has been running for 500 blocks
    /// without being filled. This likely means something went wrong with the auction creation,
    /// and it should be re-created.
    ///
    /// ### Arguments
    /// * `auction_type` - The type of auction. Only 0 (UserLiquidation) is supported; types 1 (bad debt) and 2 (interest)
    ///                    are rejected with `BadRequest`
    /// * `user` - The Address involved in the auction
    ///
    /// ### Panics
    /// * If the auction does not exist
    /// * If the auction is not stale
    fn del_auction(e: Env, auction_type: u32, user: Address);

    /// Check and handle bad debt for a user.
    /// * Calls targeting the backstop address are rejected (`BadRequest`); backstop bad debt handling is unsupported.
    /// * If the user has no remaining collateral value, their same-reserve supply repays their debt first,
    ///   and any remaining debt is written off against suppliers of that reserve.
    /// * The backstop does not absorb bad debt.
    ///
    /// ### Arguments
    /// * `user` - The address of the user to check for bad debt
    ///
    /// ### Panics
    /// * If there is no bad debt to handle
    /// * If there is an ongoing auction for the user
    fn bad_debt(e: Env, user: Address);
}

#[contractimpl]
impl PoolContract {
    /// Initialize the pool
    ///
    /// ### Arguments
    /// Creator supplied:
    /// * `admin` - The Address for the admin
    /// * `name` - The name of the pool
    /// * `oracle` - The contract address of the oracle
    /// * `backstop_take_rate` - The take rate for the backstop (7 decimals)
    /// * `max_positions` - The maximum number of positions a user is permitted to have
    /// * `min_collateral` - The minimum collateral required to open a borrow position in the oracles base asset
    ///
    /// Pool Factory supplied:
    /// * `backstop_id` - The contract address of the pool's backstop module
    /// * `blnd_id` - The contract ID of the BLND token
    pub fn __constructor(
        e: Env,
        admin: Address,
        name: String,
        oracle: Address,
        bstop_rate: u32,
        max_positions: u32,
        min_collateral: i128,
        backstop_id: Address,
        blnd_id: Address,
    ) {
        admin.require_auth();

        pool::execute_initialize(
            &e,
            &admin,
            &name,
            &oracle,
            &bstop_rate,
            &max_positions,
            &min_collateral,
            &backstop_id,
            &blnd_id,
        );
    }
}

#[contractimpl]
impl Pool for PoolContract {
    fn propose_admin(e: Env, new_admin: Address) {
        storage::extend_instance(&e);
        let admin = storage::get_admin(&e);
        admin.require_auth();

        storage::set_proposed_admin(&e, &new_admin);
    }

    fn accept_admin(e: Env) {
        storage::extend_instance(&e);

        if let Some(proposed_admin) = storage::get_proposed_admin(&e) {
            proposed_admin.require_auth();
            let cur_admin = storage::get_admin(&e);

            storage::set_admin(&e, &proposed_admin);

            PoolEvents::set_admin(&e, cur_admin, proposed_admin);
        } else {
            panic_with_error!(&e, PoolError::BadRequest);
        }
    }

    fn update_pool(e: Env, backstop_take_rate: u32, max_positions: u32, min_collateral: i128) {
        panic_with_error!(&e, PoolError::BadRequest);
    }

    fn queue_set_reserve(e: Env, asset: Address, metadata: ReserveConfig) {
        storage::extend_instance(&e);
        let admin = storage::get_admin(&e);
        admin.require_auth();

        pool::execute_queue_set_reserve(&e, &asset, &metadata);

        PoolEvents::queue_set_reserve(&e, admin, asset, metadata);
    }

    fn cancel_set_reserve(e: Env, asset: Address) {
        storage::extend_instance(&e);
        let admin = storage::get_admin(&e);
        admin.require_auth();

        pool::execute_cancel_queued_set_reserve(&e, &asset);

        PoolEvents::cancel_set_reserve(&e, admin, asset);
    }

    fn set_reserve(e: Env, asset: Address) -> u32 {
        storage::extend_instance(&e);

        let index = pool::execute_set_reserve(&e, &asset);

        PoolEvents::set_reserve(&e, asset, index);
        index
    }

    fn get_config(e: Env) -> PoolConfig {
        storage::get_pool_config(&e)
    }

    fn get_admin(e: Env) -> Address {
        storage::get_admin(&e)
    }

    fn get_reserve_list(e: Env) -> Vec<Address> {
        storage::get_res_list(&e)
    }

    fn get_reserve(e: Env, asset: Address) -> Reserve {
        let pool_config = storage::get_pool_config(&e);
        Reserve::load(&e, &pool_config, &asset)
    }

    fn get_positions(e: Env, address: Address) -> Positions {
        storage::get_user_positions(&e, &address)
    }

    fn submit(
        e: Env,
        from: Address,
        spender: Address,
        to: Address,
        requests: Vec<Request>,
    ) -> Positions {
        storage::extend_instance(&e);
        spender.require_auth();
        if from != spender {
            from.require_auth();
        }

        pool::execute_submit(&e, &from, &spender, &to, requests, false)
    }

    fn submit_with_allowance(
        e: Env,
        from: Address,
        spender: Address,
        to: Address,
        requests: Vec<Request>,
    ) -> Positions {
        storage::extend_instance(&e);
        spender.require_auth();
        if from != spender {
            from.require_auth();
        }

        pool::execute_submit(&e, &from, &spender, &to, requests, true)
    }

    fn flash_loan(
        e: Env,
        from: Address,
        flash_loan: FlashLoan,
        requests: Vec<Request>,
    ) -> Positions {
        panic_with_error!(&e, PoolError::BadRequest);
    }

    fn update_status(e: Env) -> u32 {
        storage::extend_instance(&e);
        let new_status = pool::execute_update_pool_status(&e);

        PoolEvents::set_status(&e, new_status);
        new_status
    }

    fn set_status(e: Env, pool_status: u32) {
        storage::extend_instance(&e);
        let admin = storage::get_admin(&e);
        admin.require_auth();
        pool::execute_set_pool_status(&e, pool_status);

        PoolEvents::set_status_admin(&e, admin, pool_status);
    }

    fn gulp(e: Env, asset: Address) -> i128 {
        storage::extend_instance(&e);
        let token_delta = pool::execute_gulp(&e, &asset);

        PoolEvents::gulp(&e, asset, token_delta);
        token_delta
    }

    /********* Emission Functions **********/

    fn gulp_emissions(e: Env) -> i128 {
        storage::extend_instance(&e);
        let emissions = emissions::gulp_emissions(&e);

        PoolEvents::gulp_emissions(&e, emissions);
        emissions
    }

    fn set_emissions_config(e: Env, res_emission_metadata: Vec<ReserveEmissionMetadata>) {
        panic_with_error!(&e, PoolError::BadRequest);
    }

    fn claim(e: Env, from: Address, reserve_token_ids: Vec<u32>, to: Address) -> i128 {
        storage::extend_instance(&e);
        from.require_auth();

        let amount_claimed = emissions::execute_claim(&e, &from, &reserve_token_ids, &to);

        PoolEvents::claim(&e, from, reserve_token_ids, amount_claimed);

        amount_claimed
    }

    fn get_reserve_emissions(e: Env, reserve_token_index: u32) -> Option<ReserveEmissionData> {
        storage::get_res_emis_data(&e, &reserve_token_index)
    }

    fn get_user_emissions(
        e: Env,
        user: Address,
        reserve_token_index: u32,
    ) -> Option<UserEmissionData> {
        storage::get_user_emissions(&e, &user, &reserve_token_index)
    }

    /***** Auction / Liquidation Functions *****/

    fn new_auction(
        e: Env,
        auction_type: u32,
        user: Address,
        bid: Vec<Address>,
        lot: Vec<Address>,
        percent: u32,
    ) -> AuctionData {
        storage::extend_instance(&e);

        let auction_data = auctions::create_auction(&e, auction_type, &user, &bid, &lot, percent);

        PoolEvents::new_auction(&e, auction_type, user, percent, auction_data.clone());
        auction_data
    }

    fn get_auction(e: Env, auction_type: u32, user: Address) -> AuctionData {
        storage::get_auction(&e, &auction_type, &user)
    }

    fn del_auction(e: Env, auction_type: u32, user: Address) {
        storage::extend_instance(&e);

        auctions::delete_stale_auction(&e, auction_type, &user);

        PoolEvents::delete_auction(&e, auction_type, user);
    }

    fn bad_debt(e: Env, user: Address) {
        storage::extend_instance(&e);

        pool::bad_debt(&e, &user);
    }
}
