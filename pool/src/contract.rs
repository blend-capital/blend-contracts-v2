use crate::{
    auctions::{self, AuctionData},
    emissions::{self, ReserveEmissionMetadata},
    events::PoolEvents,
    pool::{self, FlashLoan, Positions, Request, Reserve},
    storage::{self, ReserveConfig},
    PoolConfig, ReserveEmissionData, UserEmissionData,
};
use soroban_sdk::{contract, contractclient, contractimpl, Address, Env, String, Vec};

/// ### Pool
///
/// An isolated money market pool.
#[contract]
pub struct PoolContract;

#[contractclient(name = "PoolClient")]
pub trait Pool {
    /// (Admin only) Set a new address as the admin of this pool
    ///
    /// ### Arguments
    /// * `new_admin` - The new admin address
    ///
    /// ### Panics
    /// If the caller is not the admin
    fn set_admin(e: Env, new_admin: Address);

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

    /// (Admin only) Executes the queued set of a reserve in the pool
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

    /// Fetch information about a reserve, updated to the current ledger
    ///
    /// ### Arguments
    /// * `asset` - The address of the reserve asset
    fn get_reserve(e: Env, asset: Address) -> Reserve;

    /// Fetch data about the pool and its reserves.
    ///
    /// Useful for external integrations that need to load all data about the pool
    ///
    /// Returns a tuple with the pool configuration and a vector of reserves, where each reserve
    /// is updated to the current ledger.
    fn get_market(e: Env) -> (PoolConfig, Vec<Reserve>);

    /// Fetch the positions for an address
    ///
    /// ### Arguments
    /// * `address` - The address to fetch positions for
    fn get_positions(e: Env, address: Address) -> Positions;

    /// Submit a set of requests to the pool where 'from' takes on the position, 'sender' sends any
    /// required tokens to the pool and 'to' receives any tokens sent from the pool.
    ///
    /// Returns the new positions for 'from'
    ///
    /// ### Arguments
    /// * `from` - The address of the user whose positions are being modified
    /// * `spender` - The address of the user who is sending tokens to the pool
    /// * `to` - The address of the user who is receiving tokens from the pool
    /// * `requests` - A vec of requests to be processed
    ///
    /// ### Panics
    /// If the request is not able to be completed for cases like insufficient funds or invalid health factor
    fn submit(
        e: Env,
        from: Address,
        spender: Address,
        to: Address,
        requests: Vec<Request>,
    ) -> Positions;

    /// Submit a set of requests to the pool where 'from' takes on the position, 'spender' sends any
    /// required tokens to the pool using transfer_from and 'to' receives any tokens sent from the pool.
    ///
    /// Returns the new positions for 'from'
    ///
    /// ### Arguments
    /// * `from` - The address of the user whose positions are being modified
    /// * `spender` - The address of the user who is sending tokens to the pool
    /// * `to` - The address of the user who is receiving tokens from the pool
    /// * `requests` - A vec of requests to be processed
    ///
    /// ### Panics
    /// If the request is not able to be completed for cases like insufficient funds, insufficient allowance, or invalid health factor
    fn submit_with_allowance(
        e: Env,
        from: Address,
        spender: Address,
        to: Address,
        requests: Vec<Request>,
    ) -> Positions;

    /// Submit flash loan and a set of requests to the pool where 'from' takes on the position. The flash loan will be invoked using
    /// the 'flash_loan' arguments and 'from' as the caller. For the requests, 'from' sends any required tokens to the pool
    /// using transfer_from and receives any tokens sent from the pool.
    ///
    /// Returns the new positions for 'from'
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

    /// (Admin only) Pool status is changed to "pool_status"
    /// * 0 = admin active - requires that the backstop threshold is met
    ///                 and less than 50% of backstop deposits are queued for withdrawal
    /// * 2 = admin on-ice - requires that less than 75% of backstop deposits are queued for withdrawal
    /// * 4 = admin frozen - can always be set
    ///
    /// ### Arguments
    /// * 'pool_status' - The pool status to be set
    ///
    /// ### Panics
    /// If the caller is not the admin
    /// If the specified conditions are not met for the status to be set
    fn set_status(e: Env, pool_status: u32);

    /// Gulps unaccounted for tokens to the backstop credit so they aren't lost. This is most relevant
    /// for rebasing tokens where the token balance of the pool can increase without any corresponding
    /// transfer.
    ///
    /// Blend Pools do not support fee-on-transaction tokens, or any tokens in which the pools balance
    /// can decrease without any corresponding withdraw. Thus, negative token deltas are ignored.
    ///
    /// ### Arguments
    /// * `asset` - The address of the asset to gulp
    ///
    /// Returns the amount of tokens gulped
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
    /// * If the sum of ReserveEmissionMetadata shares is greater than 1
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

    /// Create a new auction. Auctions are used to process liquidations, bad debt, and interest.
    ///
    /// ### Arguments
    /// * `auction_type` - The type of auction, 0 for liquidation auction, 1 for bad debt auction, and 2 for interest auction
    /// * `user` - The Address involved in the auction. This is generally the source of the assets being auctioned.
    ///            For bad debt and interest auctions, this is expected to be the backstop address.
    /// * `bid` - The set of assets to include in the auction bid, or what the filler spends when filling the auction.
    /// * `lot` - The set of assets to include in the auction lot, or what the filler receives when filling the auction.
    /// * `percent` - The percent of the assets to be auctioned off as a percentage (15 => 15%). For bad debt and interest auctions.
    ///               this is expected to be 100.
    fn new_auction(
        e: Env,
        auction_type: u32,
        user: Address,
        bid: Vec<Address>,
        lot: Vec<Address>,
        percent: u32,
    ) -> AuctionData;

    /// Fetch an auction from the ledger. Returns a quote based on the current block.
    ///
    /// ### Arguments
    /// * `auction_type` - The type of auction, 0 for liquidation auction, 1 for bad debt auction, and 2 for interest auction
    /// * `user` - The Address involved in the auction
    ///
    /// ### Panics
    /// If the auction does not exist
    fn get_auction(e: Env, auction_type: u32, user: Address) -> AuctionData;
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
    fn set_admin(e: Env, new_admin: Address) {
        storage::extend_instance(&e);
        let admin = storage::get_admin(&e);
        admin.require_auth();
        new_admin.require_auth();

        storage::set_admin(&e, &new_admin);

        PoolEvents::set_admin(&e, admin, new_admin);
    }

    fn update_pool(e: Env, backstop_take_rate: u32, max_positions: u32, min_collateral: i128) {
        storage::extend_instance(&e);
        let admin = storage::get_admin(&e);
        admin.require_auth();

        pool::execute_update_pool(&e, backstop_take_rate, max_positions, min_collateral);

        PoolEvents::update_pool(&e, admin, backstop_take_rate, max_positions, min_collateral);
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

    fn get_reserve(e: Env, asset: Address) -> Reserve {
        let pool_config = storage::get_pool_config(&e);
        Reserve::load(&e, &pool_config, &asset)
    }

    fn get_market(e: Env) -> (PoolConfig, Vec<Reserve>) {
        let pool_config = storage::get_pool_config(&e);
        let res_list = storage::get_res_list(&e);
        let mut reserves = Vec::<Reserve>::new(&e);
        for res_address in res_list.iter() {
            let res = Reserve::load(&e, &pool_config, &res_address);
            reserves.push_back(res);
        }
        (pool_config, reserves)
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
        storage::extend_instance(&e);
        from.require_auth();

        pool::execute_submit_with_flash_loan(&e, &from, flash_loan, requests)
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
        let admin = storage::get_admin(&e);
        admin.require_auth();

        emissions::set_pool_emissions(&e, res_emission_metadata);
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
}
