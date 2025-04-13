use crate::{contract::require_nonnegative, emissions, storage, BackstopError};
use sep_41_token::TokenClient;
use soroban_sdk::{panic_with_error, Address, Env};

use super::require_is_from_pool_factory;

/// Perform a deposit into the backstop module
pub fn execute_deposit(e: &Env, from: &Address, pool_address: &Address, amount: i128) -> i128 {
    require_nonnegative(e, amount);
    if from == pool_address || from == &e.current_contract_address() {
        panic_with_error!(e, &BackstopError::BadRequest)
    }
    let mut pool_balance = storage::get_pool_balance(e, pool_address);
    require_is_from_pool_factory(e, pool_address, pool_balance.shares);
    let mut user_balance = storage::get_user_balance(e, pool_address, from);

    emissions::update_emissions(e, pool_address, &pool_balance, from, &user_balance);

    let backstop_token_client = TokenClient::new(e, &storage::get_backstop_token(e));
    backstop_token_client.transfer(from, &e.current_contract_address(), &amount);

    let to_mint = pool_balance.convert_to_shares(amount);
    if to_mint <= 0 {
        panic_with_error!(e, &BackstopError::InvalidShareMintAmount);
    }
    pool_balance.deposit(amount, to_mint);
    user_balance.add_shares(to_mint);

    storage::set_pool_balance(e, pool_address, &pool_balance);
    storage::set_user_balance(e, pool_address, from, &user_balance);

    to_mint
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{testutils::Address as _, Address};

    use crate::{
        backstop::{execute_donate, execute_draw},
        constants::SCALAR_7,
        testutils::{create_backstop, create_backstop_token, create_mock_pool_factory},
    };

    use super::*;

    #[test]
    fn test_execute_deposit() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);
        let frodo = Address::generate(&e);
        let pool_0_id = Address::generate(&e);
        let pool_1_id = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);
        backstop_token_client.mint(&frodo, &100_0000000);

        let (_, mock_pool_factory_client) = create_mock_pool_factory(&e, &backstop_address);
        mock_pool_factory_client.set_pool(&pool_0_id);
        mock_pool_factory_client.set_pool(&pool_1_id);

        backstop_token_client.approve(
            &frodo,
            &backstop_address,
            &25_0000000,
            &e.ledger().sequence(),
        );
        // initialize pool 0 with funds + some profit
        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &frodo, &pool_0_id, 25_0000000);
            execute_donate(&e, &frodo, &pool_0_id, 25_0000000);
        });

        e.as_contract(&backstop_address, || {
            let shares_0 = execute_deposit(&e, &samwise, &pool_0_id, 30_0000000);
            let shares_1 = execute_deposit(&e, &samwise, &pool_1_id, 70_0000000);

            let new_pool_0_balance = storage::get_pool_balance(&e, &pool_0_id);
            assert_eq!(new_pool_0_balance.shares, 40_0000000);
            assert_eq!(new_pool_0_balance.tokens, 80_0000000);
            assert_eq!(new_pool_0_balance.q4w, 0);

            let new_user_balance_0 = storage::get_user_balance(&e, &pool_0_id, &samwise);
            assert_eq!(new_user_balance_0.shares, shares_0);
            assert_eq!(shares_0, 15_0000000);

            let new_pool_1_balance = storage::get_pool_balance(&e, &pool_1_id);
            assert_eq!(new_pool_1_balance.shares, 70_0000000);
            assert_eq!(new_pool_1_balance.tokens, 70_0000000);
            assert_eq!(new_pool_1_balance.q4w, 0);

            let new_user_balance_1 = storage::get_user_balance(&e, &pool_1_id, &samwise);
            assert_eq!(new_user_balance_1.shares, shares_1);
            assert_eq!(shares_1, 70_0000000);

            assert_eq!(
                backstop_token_client.balance(&backstop_address),
                150_0000000
            );
            assert_eq!(backstop_token_client.balance(&samwise), 0);
        });
    }

    #[test]
    #[should_panic]
    fn test_execute_deposit_too_many_tokens() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let pool_0_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);

        let (_, mock_pool_factory_client) = create_mock_pool_factory(&e, &backstop_address);
        mock_pool_factory_client.set_pool(&pool_0_id);

        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &samwise, &pool_0_id, 100_0000001);

            assert!(false);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #8)")]
    fn test_execute_deposit_negative_tokens() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let pool_0_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);

        let (_, mock_pool_factory_client) = create_mock_pool_factory(&e, &backstop_address);
        mock_pool_factory_client.set_pool(&pool_0_id);

        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &samwise, &pool_0_id, -100);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1000)")]
    fn test_execute_deposit_from_is_to() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let pool_0_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);

        let (_, mock_pool_factory_client) = create_mock_pool_factory(&e, &backstop_address);
        mock_pool_factory_client.set_pool(&pool_0_id);

        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &pool_0_id, &pool_0_id, 100);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1000)")]
    fn test_execute_deposit_from_self() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let pool_0_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);

        let (_, mock_pool_factory_client) = create_mock_pool_factory(&e, &backstop_address);
        mock_pool_factory_client.set_pool(&pool_0_id);

        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &backstop_address, &pool_0_id, 100);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1004)")]
    fn text_execute_deposit_not_pool() {
        let e = Env::default();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let pool_0_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);

        create_mock_pool_factory(&e, &backstop_address);

        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &samwise, &pool_0_id, 100);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1005)")]
    fn test_execute_deposit_zero_share_mint() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);
        let frodo = Address::generate(&e);
        let pool_0_id = Address::generate(&e);
        let pool_1_id = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);
        backstop_token_client.mint(&frodo, &100_000_000_0000000);

        let (_, mock_pool_factory_client) = create_mock_pool_factory(&e, &backstop_address);
        mock_pool_factory_client.set_pool(&pool_0_id);
        mock_pool_factory_client.set_pool(&pool_1_id);

        backstop_token_client.approve(
            &frodo,
            &backstop_address,
            &(10_000_000 * SCALAR_7),
            &e.ledger().sequence(),
        );
        // initialize pool 0 with funds + some profit
        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &frodo, &pool_0_id, SCALAR_7);
            execute_donate(&e, &frodo, &pool_0_id, 10_000_000 * SCALAR_7);
        });

        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &samwise, &pool_0_id, SCALAR_7);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1005)")]
    fn test_execute_deposit_drained_backstop() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths_allowing_non_root_auth();

        let backstop_address = create_backstop(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);
        let frodo = Address::generate(&e);
        let pool_0_id = Address::generate(&e);
        let pool_1_id = Address::generate(&e);

        let (_, backstop_token_client) = create_backstop_token(&e, &backstop_address, &bombadil);
        backstop_token_client.mint(&samwise, &100_0000000);
        backstop_token_client.mint(&frodo, &100_000_000_0000000);

        let (_, mock_pool_factory_client) = create_mock_pool_factory(&e, &backstop_address);
        mock_pool_factory_client.set_pool(&pool_0_id);
        mock_pool_factory_client.set_pool(&pool_1_id);

        backstop_token_client.approve(
            &frodo,
            &backstop_address,
            &(10_000_000 * SCALAR_7),
            &e.ledger().sequence(),
        );
        // initialize pool 0 with funds than drain the backstop
        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &frodo, &pool_0_id, SCALAR_7);
            execute_draw(&e, &pool_0_id, SCALAR_7, &frodo);
        });

        e.as_contract(&backstop_address, || {
            execute_deposit(&e, &samwise, &pool_0_id, SCALAR_7);
        });
    }
}
