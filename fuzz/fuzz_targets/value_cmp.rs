// SPDX-License-Identifier: AGPL-3.0-only
/*
 * Copyright 2025-2026 Triton One Limited. All rights reserved.
 */

//! `ValueCmp::values_match` on any account data: no panic, and an operand outside the data
//! never matches.

#![no_main]

use arbitrary::Unstructured;
use cloudbreak_core::modules::rpc_filter_type::{
    Operand, RpcFilterType, account_matches_value_cmps,
};
use cloudbreak_fuzz::{value_cmp, value_size};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let mut u = Unstructured::new(input);
    let Ok(cmp) = value_cmp(&mut u) else {
        return;
    };
    let data = u.take_rest();

    let outside = [&cmp.left, &cmp.right].into_iter().any(|operand| {
        matches!(operand, Operand::Mem { offset, value_type }
            if offset.checked_add(value_size(value_type)).is_none_or(|end| end > data.len()))
    });
    let result = cmp.values_match(data);
    if outside {
        assert!(
            result.is_err(),
            "{cmp:?} matched outside {} bytes",
            data.len()
        );
    }

    let filter = RpcFilterType::ValueCmp(cmp);
    let matched = account_matches_value_cmps(std::slice::from_ref(&filter), data);
    assert_eq!(matched, result.unwrap_or(false));
    let _ = filter.verify();
});
