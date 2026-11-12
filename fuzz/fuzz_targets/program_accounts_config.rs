// SPDX-License-Identifier: AGPL-3.0-only
/*
 * Copyright 2025-2026 Triton One Limited. All rights reserved.
 */

//! The vendored `RpcProgramAccountsConfig` against Agave's on any JSON without `valueCmp`: both
//! parse it or both reject it, and each filter passes or fails `verify` in both.

#![no_main]

use cloudbreak_core::modules::rpc_filter_type::RpcProgramAccountsConfig;
use libfuzzer_sys::fuzz_target;
use solana_rpc_client_api::config::RpcProgramAccountsConfig as AgaveConfig;

fuzz_target!(|input: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(input) else {
        return;
    };
    // `valueCmp` is the Cloudbreak extension that Agave rejects.
    if value.to_string().contains("valueCmp") {
        return;
    }
    let ours = serde_json::from_value::<RpcProgramAccountsConfig>(value.clone());
    let agave = serde_json::from_value::<AgaveConfig>(value.clone());
    assert_eq!(
        ours.is_ok(),
        agave.is_ok(),
        "{value}: cloudbreak {:?}, agave {:?}",
        ours.as_ref().err(),
        agave.as_ref().err()
    );
    let (Ok(ours), Ok(agave)) = (ours, agave) else {
        return;
    };
    let ours = ours.filters.unwrap_or_default();
    let agave = agave.filters.unwrap_or_default();
    assert_eq!(ours.len(), agave.len(), "{value}");
    for (ours, agave) in ours.iter().zip(&agave) {
        assert_eq!(ours.verify().is_ok(), agave.verify().is_ok(), "{value}");
    }
});
