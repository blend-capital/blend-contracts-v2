use soroban_sdk::{testutils::Address as _, Address, Env};
use moderc3156_example::{FlashLoanReceiverModifiedERC3156Client, FlashLoanReceiverModifiedERC3156};

pub fn create_flashloan_receiver<'a>(e: &Env) -> (Address, FlashLoanReceiverModifiedERC3156Client<'a>) {
    let contract_id = Address::generate(e);
    e.register_at(&contract_id, FlashLoanReceiverModifiedERC3156 {}, ());

    (contract_id.clone(), FlashLoanReceiverModifiedERC3156Client::new(e, &contract_id))
}
