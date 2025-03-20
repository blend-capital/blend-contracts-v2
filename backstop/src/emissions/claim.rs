use crate::{dependencies::CometClient, errors::BackstopError, events::BackstopEvents, storage};
use soroban_fixed_point_math::FixedPoint;
use soroban_sdk::{
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    panic_with_error, vec, Address, Env, IntoVal, Map, Symbol, Val, Vec,
};

use super::distributor::claim_emissions;

/// Perform a claim for backstop deposit emissions by a user from the backstop module
pub fn execute_claim(
    e: &Env,
    from: &Address,
    pool_addresses: &Vec<Address>,
    min_lp_tokens_out: &i128,
) -> i128 {
    if pool_addresses.is_empty() {
        panic_with_error!(e, BackstopError::BadRequest);
    }

    let mut claimed: i128 = 0;
    let mut claims: Map<Address, i128> = Map::new(e);
    for pool_id in pool_addresses.iter() {
        let pool_balance = storage::get_pool_balance(e, &pool_id);
        let user_balance = storage::get_user_balance(e, &pool_id, from);
        let claim_amt = claim_emissions(e, &pool_id, &pool_balance, from, &user_balance);
        claimed += claim_amt;
        claims.set(pool_id.clone(), claim_amt);
    }

    if claimed > 0 {
        let blnd_id = storage::get_blnd_token(e);
        let lp_id = storage::get_backstop_token(e);
        let approval_ledger = (e.ledger().sequence() / 100000 + 1) * 100000;
        let args: Vec<Val> = vec![
            e,
            (&e.current_contract_address()).into_val(e),
            (&lp_id).into_val(e),
            (&claimed).into_val(e),
            (&approval_ledger).into_val(e),
        ];
        e.authorize_as_current_contract(vec![
            &e,
            InvokerContractAuthEntry::Contract(SubContractInvocation {
                context: ContractContext {
                    contract: blnd_id.clone(),
                    fn_name: Symbol::new(e, "approve"),
                    args: args.clone(),
                },
                sub_invocations: vec![e],
            }),
        ]);
        let lp_tokens_out = CometClient::new(e, &lp_id).dep_tokn_amt_in_get_lp_tokns_out(
            &blnd_id,
            &claimed,
            &min_lp_tokens_out,
            &e.current_contract_address(),
        );
        for pool_id in pool_addresses.iter() {
            let claim_amount = claims.get(pool_id.clone()).unwrap();
            let deposit_amount = lp_tokens_out
                .fixed_mul_floor(claim_amount, claimed)
                .unwrap();
            let mut pool_balance = storage::get_pool_balance(e, &pool_id);
            let mut user_balance = storage::get_user_balance(e, &pool_id, from);

            // Deposit LP tokens into pool backstop
            let to_mint = pool_balance.convert_to_shares(deposit_amount);
            pool_balance.deposit(deposit_amount, to_mint);
            user_balance.add_shares(to_mint);

            storage::set_pool_balance(e, &pool_id, &pool_balance);
            storage::set_user_balance(e, &pool_id, from, &user_balance);

            BackstopEvents::deposit(e, pool_id, from.clone(), deposit_amount, to_mint);
        }
        lp_tokens_out
    } else {
        0
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        backstop::{PoolBalance, UserBalance},
        storage::{BackstopEmissionData, UserEmissionData},
        testutils::{create_backstop, create_blnd_token, create_comet_lp_pool, create_usdc_token},
    };

    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        unwrap::UnwrapOptimized,
        vec,
    };

    /********** claim **********/

    #[test]
    fn test_claim() {
        let e = Env::default();
        e.mock_all_auths();
        let block_timestamp = 1500000000 + 12345;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        e.cost_estimate().budget().reset_unlimited();

        let backstop_address = create_backstop(&e);
        let pool_1_id = Address::generate(&e);
        let pool_2_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd_address, blnd_token_client) = create_blnd_token(&e, &backstop_address, &bombadil);
        let (usdc_address, _) = create_usdc_token(&e, &backstop_address, &bombadil);
        blnd_token_client.mint(&backstop_address, &100_0000000);

        let backstop_1_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1500000000,
        };
        let user_1_emissions_data = UserEmissionData {
            index: 111110000000,
            accrued: 1_2345678,
        };

        let backstop_2_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_02000000000000,
            index: 0,
            last_time: 1500010000,
        };
        let user_2_emissions_data = UserEmissionData {
            index: 0,
            accrued: 0,
        };
        let (lp_address, lp_client) =
            create_comet_lp_pool(&e, &bombadil, &blnd_address, &usdc_address);
        e.as_contract(&backstop_address, || {
            storage::set_backstop_emis_data(&e, &pool_1_id, &backstop_1_emissions_data);
            storage::set_user_emis_data(&e, &pool_1_id, &samwise, &user_1_emissions_data);
            storage::set_backstop_emis_data(&e, &pool_2_id, &backstop_2_emissions_data);
            storage::set_user_emis_data(&e, &pool_2_id, &samwise, &user_2_emissions_data);
            storage::set_backstop_token(&e, &lp_address);
            storage::set_blnd_token(&e, &blnd_address);
            storage::set_pool_balance(
                &e,
                &pool_1_id,
                &PoolBalance {
                    shares: 150_0000000,
                    tokens: 200_0000000,
                    q4w: 2_0000000,
                },
            );
            storage::set_user_balance(
                &e,
                &pool_1_id,
                &samwise,
                &UserBalance {
                    shares: 9_0000000,
                    q4w: vec![&e],
                },
            );
            storage::set_pool_balance(
                &e,
                &pool_2_id,
                &PoolBalance {
                    shares: 70_0000000,
                    tokens: 75_0000000,
                    q4w: 3_5000000,
                },
            );
            storage::set_user_balance(
                &e,
                &pool_2_id,
                &samwise,
                &UserBalance {
                    shares: 7_5000000,
                    q4w: vec![&e],
                },
            );
            let backstop_lp_balance = lp_client.balance(&backstop_address);
            let pre_pool_tokens_1 = storage::get_pool_balance(&e, &pool_1_id).tokens;
            let pre_pool_tokens_2 = storage::get_pool_balance(&e, &pool_2_id).tokens;
            let pre_pool_shares_1 = storage::get_pool_balance(&e, &pool_1_id).shares;
            let pre_pool_shares_2 = storage::get_pool_balance(&e, &pool_2_id).shares;
            let result = execute_claim(
                &e,
                &samwise,
                &vec![&e, pool_1_id.clone(), pool_2_id.clone()],
                &6_4000000,
            );
            assert_eq!(result, 6_4729327);
            assert_eq!(
                lp_client.balance(&backstop_address),
                backstop_lp_balance + 6_4729327
            );
            assert_eq!(
                blnd_token_client.balance(&backstop_address),
                100_0000000 - (76_3155136 + 5_2894736)
            );
            let sam_balance_1 = storage::get_user_balance(&e, &pool_1_id, &samwise);
            assert_eq!(sam_balance_1.shares, 9_0000000 + 4_5400275);
            let sam_balance_2 = storage::get_user_balance(&e, &pool_2_id, &samwise);
            assert_eq!(sam_balance_2.shares, 7_5000000 + 0_3915917);

            let pool_balance_1 = storage::get_pool_balance(&e, &pool_1_id);
            assert_eq!(pool_balance_1.tokens, pre_pool_tokens_1 + 6_0533700);
            assert_eq!(pool_balance_1.shares, pre_pool_shares_1 + 4_5400275);
            let pool_balance_2 = storage::get_pool_balance(&e, &pool_2_id);
            assert_eq!(pool_balance_2.tokens, pre_pool_tokens_2 + 0_4195626);
            assert_eq!(pool_balance_2.shares, pre_pool_shares_2 + 0_3915917);

            let new_backstop_1_data =
                storage::get_backstop_emis_data(&e, &pool_1_id).unwrap_optimized();
            let new_user_1_data =
                storage::get_user_emis_data(&e, &pool_1_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_1_data.last_time, block_timestamp);
            assert_eq!(new_backstop_1_data.index, 834343841621621);
            assert_eq!(new_user_1_data.accrued, 0);
            assert_eq!(new_user_1_data.index, 834343841621621);

            let new_backstop_2_data =
                storage::get_backstop_emis_data(&e, &pool_2_id).unwrap_optimized();
            let new_user_2_data =
                storage::get_user_emis_data(&e, &pool_2_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_2_data.last_time, block_timestamp);
            assert_eq!(new_backstop_2_data.index, 70526315789473);
            assert_eq!(new_user_2_data.accrued, 0);
            assert_eq!(new_user_2_data.index, 70526315789473);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #20)")]
    fn test_claim_uses_min_lp_amount() {
        let e = Env::default();
        e.mock_all_auths();
        let block_timestamp = 1500000000 + 12345;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });
        e.cost_estimate().budget().reset_unlimited();

        let backstop_address = create_backstop(&e);
        let pool_1_id = Address::generate(&e);
        let pool_2_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd_address, blnd_token_client) = create_blnd_token(&e, &backstop_address, &bombadil);
        let (usdc_address, _) = create_usdc_token(&e, &backstop_address, &bombadil);
        blnd_token_client.mint(&backstop_address, &100_0000000);

        let backstop_1_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1500000000,
        };
        let user_1_emissions_data = UserEmissionData {
            index: 111110000000,
            accrued: 1_2345678,
        };

        let backstop_2_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_02000000000000,
            index: 0,
            last_time: 1500010000,
        };
        let user_2_emissions_data = UserEmissionData {
            index: 0,
            accrued: 0,
        };
        let (lp_address, _) = create_comet_lp_pool(&e, &bombadil, &blnd_address, &usdc_address);
        e.as_contract(&backstop_address, || {
            storage::set_backstop_emis_data(&e, &pool_1_id, &backstop_1_emissions_data);
            storage::set_user_emis_data(&e, &pool_1_id, &samwise, &user_1_emissions_data);
            storage::set_backstop_emis_data(&e, &pool_2_id, &backstop_2_emissions_data);
            storage::set_user_emis_data(&e, &pool_2_id, &samwise, &user_2_emissions_data);
            storage::set_backstop_token(&e, &lp_address);
            storage::set_blnd_token(&e, &blnd_address);
            storage::set_pool_balance(
                &e,
                &pool_1_id,
                &PoolBalance {
                    shares: 150_0000000,
                    tokens: 200_0000000,
                    q4w: 2_0000000,
                },
            );
            storage::set_user_balance(
                &e,
                &pool_1_id,
                &samwise,
                &UserBalance {
                    shares: 9_0000000,
                    q4w: vec![&e],
                },
            );
            storage::set_pool_balance(
                &e,
                &pool_2_id,
                &PoolBalance {
                    shares: 70_0000000,
                    tokens: 75_0000000,
                    q4w: 3_5000000,
                },
            );
            storage::set_user_balance(
                &e,
                &pool_2_id,
                &samwise,
                &UserBalance {
                    shares: 7_5000000,
                    q4w: vec![&e],
                },
            );
            execute_claim(
                &e,
                &samwise,
                &vec![&e, pool_1_id.clone(), pool_2_id.clone()],
                &6_5000000,
            );
        });
    }

    #[test]
    fn test_claim_twice() {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.mock_all_auths();

        let block_timestamp = 1500000000 + 12345;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_address = create_backstop(&e);
        let pool_1_id = Address::generate(&e);
        let pool_2_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);

        let (blnd_address, blnd_token_client) = create_blnd_token(&e, &backstop_address, &bombadil);
        let (usdc_address, _) = create_usdc_token(&e, &backstop_address, &bombadil);
        blnd_token_client.mint(&backstop_address, &300_0000000);

        let backstop_1_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1500000000,
        };
        let user_1_emissions_data = UserEmissionData {
            index: 111110000000,
            accrued: 1_2345678,
        };

        let backstop_2_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_02000000000000,
            index: 0,
            last_time: 1500010000,
        };
        let user_2_emissions_data = UserEmissionData {
            index: 0,
            accrued: 0,
        };
        let (lp_address, lp_client) =
            create_comet_lp_pool(&e, &bombadil, &blnd_address, &usdc_address);
        e.as_contract(&backstop_address, || {
            storage::set_backstop_emis_data(&e, &pool_1_id, &backstop_1_emissions_data);
            storage::set_user_emis_data(&e, &pool_1_id, &samwise, &user_1_emissions_data);
            storage::set_backstop_emis_data(&e, &pool_2_id, &backstop_2_emissions_data);
            storage::set_user_emis_data(&e, &pool_2_id, &samwise, &user_2_emissions_data);
            storage::set_backstop_token(&e, &lp_address);
            storage::set_blnd_token(&e, &blnd_address);
            storage::set_pool_balance(
                &e,
                &pool_1_id,
                &PoolBalance {
                    shares: 150_0000000,
                    tokens: 200_0000000,
                    q4w: 2_0000000,
                },
            );
            storage::set_user_balance(
                &e,
                &pool_1_id,
                &samwise,
                &UserBalance {
                    shares: 9_0000000,
                    q4w: vec![&e],
                },
            );
            storage::set_pool_balance(
                &e,
                &pool_2_id,
                &PoolBalance {
                    shares: 70_0000000,
                    tokens: 75_0000000,
                    q4w: 3_5000000,
                },
            );
            storage::set_user_balance(
                &e,
                &pool_2_id,
                &samwise,
                &UserBalance {
                    shares: 7_5000000,
                    q4w: vec![&e],
                },
            );
            let backstop_lp_balance = lp_client.balance(&backstop_address);
            let pre_pool_tokens_1 = storage::get_pool_balance(&e, &pool_1_id).tokens;
            let pre_pool_tokens_2 = storage::get_pool_balance(&e, &pool_2_id).tokens;
            let pre_pool_shares_1 = storage::get_pool_balance(&e, &pool_1_id).shares;
            let pre_pool_shares_2 = storage::get_pool_balance(&e, &pool_2_id).shares;
            let result = execute_claim(
                &e,
                &samwise,
                &vec![&e, pool_1_id.clone(), pool_2_id.clone()],
                &6_4000000,
            );
            assert_eq!(result, 6_4729327);
            assert_eq!(
                lp_client.balance(&backstop_address),
                backstop_lp_balance + 6_4729327
            );
            assert_eq!(
                blnd_token_client.balance(&backstop_address),
                300_0000000 - (76_3155136 + 5_2894736)
            );
            let sam_balance_1 = storage::get_user_balance(&e, &pool_1_id, &samwise);
            assert_eq!(sam_balance_1.shares, 9_0000000 + 4_5400275);
            let sam_balance_2 = storage::get_user_balance(&e, &pool_2_id, &samwise);
            assert_eq!(sam_balance_2.shares, 7_5000000 + 0_3915917);

            let pool_balance_1 = storage::get_pool_balance(&e, &pool_1_id);
            assert_eq!(pool_balance_1.tokens, pre_pool_tokens_1 + 6_0533700);
            assert_eq!(pool_balance_1.shares, pre_pool_shares_1 + 4_5400275);
            let pool_balance_2 = storage::get_pool_balance(&e, &pool_2_id);
            assert_eq!(pool_balance_2.tokens, pre_pool_tokens_2 + 0_4195626);
            assert_eq!(pool_balance_2.shares, pre_pool_shares_2 + 0_3915917);

            let new_backstop_1_data =
                storage::get_backstop_emis_data(&e, &pool_1_id).unwrap_optimized();
            let new_user_1_data =
                storage::get_user_emis_data(&e, &pool_1_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_1_data.last_time, block_timestamp);
            assert_eq!(new_backstop_1_data.index, 834343841621621);
            assert_eq!(new_user_1_data.accrued, 0);
            assert_eq!(new_user_1_data.index, 834343841621621);

            let new_backstop_2_data =
                storage::get_backstop_emis_data(&e, &pool_2_id).unwrap_optimized();
            let new_user_2_data =
                storage::get_user_emis_data(&e, &pool_2_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_2_data.last_time, block_timestamp);
            assert_eq!(new_backstop_2_data.index, 70526315789473);
            assert_eq!(new_user_2_data.accrued, 0);
            assert_eq!(new_user_2_data.index, 70526315789473);

            let block_timestamp_1 = 1500000000 + 12345 + 12345;
            e.ledger().set(LedgerInfo {
                timestamp: block_timestamp_1,
                protocol_version: 22,
                sequence_number: 0,
                network_id: Default::default(),
                base_reserve: 10,
                min_temp_entry_ttl: 10,
                min_persistent_entry_ttl: 10,
                max_entry_ttl: 3110400,
            });
            let backstop_lp_balance = lp_client.balance(&backstop_address);
            let pre_samwise_balance_1 = storage::get_user_balance(&e, &pool_1_id, &samwise).shares;
            let pre_samwise_balance_2 = storage::get_user_balance(&e, &pool_2_id, &samwise).shares;
            let pre_pool_tokens_1 = storage::get_pool_balance(&e, &pool_1_id).tokens;
            let pre_pool_tokens_2 = storage::get_pool_balance(&e, &pool_2_id).tokens;
            let pre_pool_shares_1 = storage::get_pool_balance(&e, &pool_1_id).shares;
            let pre_pool_shares_2 = storage::get_pool_balance(&e, &pool_2_id).shares;
            let result_1 = execute_claim(
                &e,
                &samwise,
                &vec![&e, pool_1_id.clone(), pool_2_id.clone()],
                &10_7000000,
            );
            assert_eq!(result_1, 10_7836702);
            assert_eq!(
                blnd_token_client.balance(&backstop_address),
                300_0000000 - (109_5788706 + 29_1282348) - (76_3155136 + 5_2894736)
            );
            assert_eq!(
                lp_client.balance(&backstop_address),
                backstop_lp_balance + 8_5191194 + 2_2645507 + 1
            );
            let sam_balance_1 = storage::get_user_balance(&e, &pool_1_id, &samwise);
            assert_eq!(sam_balance_1.shares, pre_samwise_balance_1 + 6_3893395);
            let sam_balance_2 = storage::get_user_balance(&e, &pool_2_id, &samwise);
            assert_eq!(sam_balance_2.shares, pre_samwise_balance_2 + 2_1135806);

            let pool_balance_1 = storage::get_pool_balance(&e, &pool_1_id);
            assert_eq!(pool_balance_1.tokens, pre_pool_tokens_1 + 8_5191194);
            assert_eq!(pool_balance_1.shares, pre_pool_shares_1 + 6_3893395);
            let pool_balance_2 = storage::get_pool_balance(&e, &pool_2_id);
            assert_eq!(pool_balance_2.tokens, pre_pool_tokens_2 + 2_2645507);
            assert_eq!(pool_balance_2.shares, pre_pool_shares_2 + 2_1135806);
            let new_backstop_1_data =
                storage::get_backstop_emis_data(&e, &pool_1_id).unwrap_optimized();
            let new_user_1_data =
                storage::get_user_emis_data(&e, &pool_1_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_1_data.last_time, block_timestamp_1);
            assert_eq!(new_backstop_1_data.index, 1643639618102322);
            assert_eq!(new_user_1_data.accrued, 0);
            assert_eq!(new_user_1_data.index, 1643639618102322);

            let new_backstop_2_data =
                storage::get_backstop_emis_data(&e, &pool_2_id).unwrap_optimized();
            let new_user_2_data =
                storage::get_user_emis_data(&e, &pool_2_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_2_data.last_time, block_timestamp_1);
            assert_eq!(new_backstop_2_data.index, 439631002529944);
            assert_eq!(new_user_2_data.accrued, 0);
            assert_eq!(new_user_2_data.index, 439631002529944);
        });
    }

    #[test]
    fn test_claim_no_deposits() {
        let e = Env::default();
        e.mock_all_auths();
        let block_timestamp = 1500000000 + 12345;
        e.ledger().set(LedgerInfo {
            timestamp: block_timestamp,
            protocol_version: 22,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let backstop_address = create_backstop(&e);
        let pool_1_id = Address::generate(&e);
        let pool_2_id = Address::generate(&e);
        let bombadil = Address::generate(&e);
        let samwise = Address::generate(&e);
        let frodo = Address::generate(&e);

        let (_, blnd_token_client) = create_blnd_token(&e, &backstop_address, &bombadil);
        blnd_token_client.mint(&backstop_address, &100_0000000);

        let backstop_1_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_10000000000000,
            index: 222220000000,
            last_time: 1500000000,
        };

        let backstop_2_emissions_data = BackstopEmissionData {
            expiration: 1500000000 + 7 * 24 * 60 * 60,
            eps: 0_02000000000000,
            index: 0,
            last_time: 1500010000,
        };
        e.as_contract(&backstop_address, || {
            storage::set_backstop_emis_data(&e, &pool_1_id, &backstop_1_emissions_data);
            storage::set_backstop_emis_data(&e, &pool_2_id, &backstop_2_emissions_data);

            storage::set_pool_balance(
                &e,
                &pool_1_id,
                &PoolBalance {
                    shares: 150_0000000,
                    tokens: 200_0000000,
                    q4w: 0,
                },
            );
            storage::set_pool_balance(
                &e,
                &pool_2_id,
                &PoolBalance {
                    shares: 70_0000000,
                    tokens: 75_0000000,
                    q4w: 0,
                },
            );

            let result = execute_claim(
                &e,
                &samwise,
                &vec![&e, pool_1_id.clone(), pool_2_id.clone()],
                &0,
            );
            assert_eq!(result, 0);
            assert_eq!(blnd_token_client.balance(&frodo), 0);
            assert_eq!(blnd_token_client.balance(&backstop_address), 100_0000000);

            let new_backstop_1_data =
                storage::get_backstop_emis_data(&e, &pool_1_id).unwrap_optimized();
            let new_user_1_data =
                storage::get_user_emis_data(&e, &pool_1_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_1_data.last_time, block_timestamp);
            assert_eq!(new_backstop_1_data.index, 823222220000000);
            assert_eq!(new_user_1_data.accrued, 0);
            assert_eq!(new_user_1_data.index, 823222220000000);

            let new_backstop_2_data =
                storage::get_backstop_emis_data(&e, &pool_2_id).unwrap_optimized();
            let new_user_2_data =
                storage::get_user_emis_data(&e, &pool_2_id, &samwise).unwrap_optimized();
            assert_eq!(new_backstop_2_data.last_time, block_timestamp);
            assert_eq!(new_backstop_2_data.index, 67000000000000);
            assert_eq!(new_user_2_data.accrued, 0);
            assert_eq!(new_user_2_data.index, 67000000000000);
        });
    }
}
