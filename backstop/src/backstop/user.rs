use soroban_sdk::{contracttype, panic_with_error, vec, Env, Vec};

use crate::{
    constants::{MAX_Q4W_SIZE, Q4W_LOCK_TIME},
    errors::BackstopError,
};

/// A deposit that is queued for withdrawal
#[derive(Clone)]
#[contracttype]
pub struct Q4W {
    pub amount: i128, // the amount of shares queued for withdrawal
    pub exp: u64,     // the expiration of the withdrawal
}

/// A deposit that is queued for withdrawal
#[derive(Clone)]
#[contracttype]
pub struct UserBalance {
    pub shares: i128,  // the balance of shares the user owns
    pub q4w: Vec<Q4W>, // a list of queued withdrawals
}

impl UserBalance {
    pub fn env_default(e: &Env) -> UserBalance {
        UserBalance {
            shares: 0,
            q4w: vec![e],
        }
    }

    /***** Deposit *****/

    /// Add shares to the user
    ///
    /// ### Arguments
    /// * `to_add` - The amount of new shares the user has
    pub fn add_shares(&mut self, to_add: i128) {
        self.shares += to_add;
    }

    /***** Withdrawal Queue Management *****/

    /// Queue new shares for withdraw for the user
    ///
    /// Returns the new Q4W object
    ///
    /// ### Arguments
    /// * `to_q` - The amount of new shares to queue for withdraw
    ///
    /// ### Errors
    /// If the amount to queue is greater than the available shares
    pub fn queue_shares_for_withdrawal(&mut self, e: &Env, to_q: i128) {
        if self.shares < to_q {
            panic_with_error!(e, BackstopError::BalanceError);
        }
        if self.q4w.len() >= MAX_Q4W_SIZE {
            panic_with_error!(e, BackstopError::TooManyQ4WEntries);
        }
        self.shares = self.shares - to_q;

        // user has enough tokens to withdrawal, add Q4W
        let new_q4w = Q4W {
            amount: to_q,
            exp: e.ledger().timestamp() + Q4W_LOCK_TIME,
        };
        self.q4w.push_back(new_q4w.clone());
    }

    /// Withdraw shares from the withdrawal queue
    ///
    /// ### Arguments
    /// * `to_withdraw` - The amount of shares to withdraw from the withdrawal queue
    ///
    /// ### Errors
    /// If the user does not have enough shares currently eligible to withdraw
    #[allow(clippy::comparison_chain)]
    pub fn withdraw_shares(&mut self, e: &Env, to_withdraw: i128) {
        // validate the invoke has enough unlocked Q4W to claim
        // manage the q4w list while verifying
        let mut left_to_withdraw: i128 = to_withdraw;
        for _index in 0..self.q4w.len() {
            let mut cur_q4w = self.q4w.pop_front_unchecked();
            if cur_q4w.exp <= e.ledger().timestamp() {
                if cur_q4w.amount > left_to_withdraw {
                    // last record we need to update, but the q4w should remain
                    cur_q4w.amount -= left_to_withdraw;
                    left_to_withdraw = 0;
                    self.q4w.push_front(cur_q4w);
                    break;
                } else if cur_q4w.amount == left_to_withdraw {
                    // last record we need to update, q4w fully consumed
                    left_to_withdraw = 0;
                    break;
                } else {
                    // allow the pop to consume the record
                    left_to_withdraw -= cur_q4w.amount;
                }
            } else {
                panic_with_error!(e, BackstopError::NotExpired);
            }
        }

        if left_to_withdraw > 0 {
            panic_with_error!(e, BackstopError::BalanceError);
        }
    }

    /// Dequeue shares from the withdrawal queue. Dequeues the most recently queued shares first.
    ///
    /// ### Arguments
    /// * `to_dequeue` - The amount of shares to dequeue from the withdrawal queue
    ///
    /// ### Errors
    /// If they don't have enough queued shares to dequeue
    #[allow(clippy::comparison_chain)]
    pub fn dequeue_shares(&mut self, e: &Env, to_dequeue: i128) {
        // validate the invoke has enough unlocked Q4W to claim
        // manage the q4w list while verifying
        let mut left_to_dequeue: i128 = to_dequeue;
        for _index in 0..self.q4w.len() {
            let mut cur_q4w = self.q4w.pop_back_unchecked();
            if cur_q4w.amount > left_to_dequeue {
                // last record we need to update, but the q4w should remain
                cur_q4w.amount -= left_to_dequeue;
                left_to_dequeue = 0;
                self.q4w.push_back(cur_q4w);
                break;
            } else if cur_q4w.amount == left_to_dequeue {
                // last record we need to update, q4w fully consumed
                left_to_dequeue = 0;
                break;
            } else {
                // allow the pop to consume the record
                left_to_dequeue -= cur_q4w.amount;
            }
        }

        if left_to_dequeue > 0 {
            panic_with_error!(e, BackstopError::BalanceError);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testutils::assert_eq_vec_q4w;

    use super::*;
    use soroban_sdk::{
        testutils::{Ledger, LedgerInfo},
        vec,
    };

    /********** Share Management **********/

    #[test]
    fn test_add_shares() {
        let e = Env::default();

        let mut user = UserBalance {
            shares: 100,
            q4w: vec![&e],
        };

        let to_add = 12318972;
        user.add_shares(to_add);

        assert_eq!(user.shares, to_add + 100);
    }

    /********** Q4W Management **********/

    #[test]
    fn test_q4w_none_queued() {
        let e = Env::default();

        let mut user = UserBalance {
            shares: 1000,
            q4w: vec![&e],
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 10000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_queue = 500;
        user.queue_shares_for_withdrawal(&e, to_queue);
        assert_eq_vec_q4w(
            &user.q4w,
            &vec![
                &e,
                Q4W {
                    amount: to_queue,
                    exp: 10000 + 21 * 24 * 60 * 60,
                },
            ],
        );
    }

    #[test]
    fn test_q4w_new_placed_last() {
        let e = Env::default();

        let mut cur_q4w = vec![
            &e,
            Q4W {
                amount: 200,
                exp: 12592000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11000000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_queue = 500;
        user.queue_shares_for_withdrawal(&e, to_queue);
        cur_q4w.push_back(Q4W {
            amount: to_queue,
            exp: 11000000 + 21 * 24 * 60 * 60,
        });
        assert_eq_vec_q4w(&user.q4w, &cur_q4w);
    }

    #[test]
    fn test_q4w_new_to_max_works() {
        let e = Env::default();
        let exp = 12592000;
        let mut cur_q4w = vec![&e];
        for i in 0..20 {
            cur_q4w.push_back(Q4W {
                amount: 200,
                exp: exp + i,
            });
        }
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11000000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_queue = 500;
        user.queue_shares_for_withdrawal(&e, to_queue);
        cur_q4w.push_back(Q4W {
            amount: to_queue,
            exp: 11000000 + 21 * 24 * 60 * 60,
        });
        assert_eq_vec_q4w(&user.q4w, &cur_q4w);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1007)")]
    fn test_q4w_new_over_max_panics() {
        let e = Env::default();

        let exp = 12592000;
        let mut cur_q4w = vec![&e];
        for i in 0..21 {
            cur_q4w.push_back(Q4W {
                amount: 200,
                exp: exp + i,
            });
        }
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11000000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_queue = 500;
        user.queue_shares_for_withdrawal(&e, to_queue);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10)")]
    fn test_q4w_over_shares_panics() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 200,
                exp: 12592000,
            },
        ];
        let mut user = UserBalance {
            shares: 800,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11000000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_queue = 801;
        user.queue_shares_for_withdrawal(&e, to_queue);
    }

    // withdraw_shares

    #[test]
    #[should_panic(expected = "Error(Contract, #10)")]
    fn test_withdraw_shares_no_q4w_panics() {
        let e = Env::default();

        let mut user = UserBalance {
            shares: 1000,
            q4w: vec![&e],
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11000000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_wd = 1;
        user.withdraw_shares(&e, to_wd);
    }

    #[test]
    fn test_withdraw_shares_exact_amount() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 200,
                exp: 12592000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 12592000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_wd = 200;
        user.withdraw_shares(&e, to_wd);

        assert_eq_vec_q4w(&user.q4w, &vec![&e]);
        assert_eq!(user.shares, 1000);
    }

    #[test]
    fn test_withdraw_shares_less_than_entry() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 200,
                exp: 12592000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 12592000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_wd = 150;
        user.withdraw_shares(&e, to_wd);

        let expected_q4w = vec![
            &e,
            Q4W {
                amount: 50,
                exp: 12592000,
            },
        ];
        assert_eq_vec_q4w(&user.q4w, &expected_q4w);
        assert_eq!(user.shares, 1000);
    }

    #[test]
    fn test_withdraw_shares_multiple_entries() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 125,
                exp: 10000000,
            },
            Q4W {
                amount: 200,
                exp: 12592000,
            },
            Q4W {
                amount: 50,
                exp: 19592000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 22592000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_wd = 300;
        user.withdraw_shares(&e, to_wd);

        let expected_q4w = vec![
            &e,
            Q4W {
                amount: 25,
                exp: 12592000,
            },
            Q4W {
                amount: 50,
                exp: 19592000,
            },
        ];
        assert_eq_vec_q4w(&user.q4w, &expected_q4w);
        assert_eq!(user.shares, 1000);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1001)")]
    fn test_withdraw_shares_multiple_entries_not_exp() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 125,
                exp: 10000000,
            },
            Q4W {
                amount: 200,
                exp: 12592000,
            },
            Q4W {
                amount: 50,
                exp: 19592000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11192000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_wd = 300;
        user.withdraw_shares(&e, to_wd);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10)")]
    fn test_withdraw_shares_over_total() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 125,
                exp: 10000000,
            },
            Q4W {
                amount: 200,
                exp: 11190000,
            },
            Q4W {
                amount: 50,
                exp: 11191000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11192000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_dequeue = 376;
        user.withdraw_shares(&e, to_dequeue);
    }

    // dequeue_shares

    #[test]
    #[should_panic(expected = "Error(Contract, #10)")]
    fn test_dequeue_shares_no_q4w_panics() {
        let e = Env::default();

        let mut user = UserBalance {
            shares: 1000,
            q4w: vec![&e],
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11000000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_wd = 1;
        user.dequeue_shares(&e, to_wd);
    }

    #[test]
    fn test_dequeue_shares_exact_amount() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 200,
                exp: 10000000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 12592000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_dequeue = 200;
        user.dequeue_shares(&e, to_dequeue);

        assert_eq_vec_q4w(&user.q4w, &vec![&e]);
        assert_eq!(user.shares, 1000);
    }

    #[test]
    fn test_dequeue_shares_less_than_entry() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 200,
                exp: 14592000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 12592000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_dequeue = 150;
        user.dequeue_shares(&e, to_dequeue);

        let expected_q4w = vec![
            &e,
            Q4W {
                amount: 50,
                exp: 14592000,
            },
        ];
        assert_eq_vec_q4w(&user.q4w, &expected_q4w);
        assert_eq!(user.shares, 1000);
    }

    #[test]
    fn test_dequeue_shares_multiple_entries_dequeue_newest() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 125,
                exp: 10000000,
            },
            Q4W {
                amount: 200,
                exp: 12592000,
            },
            Q4W {
                amount: 50,
                exp: 19592000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 22592000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_dequeue = 150;
        user.dequeue_shares(&e, to_dequeue);

        let expected_q4w = vec![
            &e,
            Q4W {
                amount: 125,
                exp: 10000000,
            },
            Q4W {
                amount: 100,
                exp: 12592000,
            },
        ];
        assert_eq_vec_q4w(&user.q4w, &expected_q4w);
        assert_eq!(user.shares, 1000);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #10)")]
    fn test_dequeue_shares_over_total() {
        let e = Env::default();

        let cur_q4w = vec![
            &e,
            Q4W {
                amount: 125,
                exp: 10000000,
            },
            Q4W {
                amount: 200,
                exp: 11190000,
            },
            Q4W {
                amount: 50,
                exp: 11191000,
            },
        ];
        let mut user = UserBalance {
            shares: 1000,
            q4w: cur_q4w.clone(),
        };

        e.ledger().set(LedgerInfo {
            protocol_version: 22,
            sequence_number: 1,
            timestamp: 11192000,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 10,
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3110400,
        });

        let to_dequeue = 376;
        user.dequeue_shares(&e, to_dequeue);
    }
}
