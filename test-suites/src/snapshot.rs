//! Contract addresses and other relevant values used in the mainnet snapshot

use soroban_sdk::{testutils::EnvTestConfig, Env};

pub const USDC_ID: &str = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75";
pub const BLND_ID: &str = "CD25MNVTZDL4Y3XBCPCJXGXATV5WUHHOWMYFF4YBEGU5FCPGMYTVG5JY";
pub const XLM_ID: &str = "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA";

pub const BLND_USDC_LP_ID: &str = "CAS3FL6TLZKDGGSISDBWGGPXT3NRR4DYTZD7YOD3HMYO6LTJUVGRVEAM";

pub const EMITTER_ID: &str = "CCOQM6S7ICIUWA225O5PSJWUBEMXGFSSW2PQFO6FP4DQEKMS5DASRGRR";
pub const BACKSTOP_ID: &str = "CAO3AGAMZVRMHITL36EJ2VZQWKYRPWMQAPDQD5YEOF3GIF7T44U4JAL3";
pub const POOL_FACTORY_ID: &str = "CCZD6ESMOGMPWH2KRO4O7RGTAPGTUPFWFQBELQSS7ZUK63V3TZWETGAG";

pub const V1_POOL_ID: &str = "CDVQVKOY2YSXS2IC7KN6MNASSHPAO7UN2UR2ON4OI2SKMFJNVAMDX6DP";

// has ~3m XLM available
pub const XLM_WHALE: &str = "CBP7NO6F7FRDHSOFQBT2L2UWYIZ2PU76JKVRYAQTG3KZSQLYAOKIF2WB";

/// This is a partial snapshot, and does not include user pool data
pub fn env_from_snapshot() -> Env {
    let mut env = Env::from_ledger_snapshot_file("./src/mainnet-55261759-snapshot.json");
    env.set_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env
}
