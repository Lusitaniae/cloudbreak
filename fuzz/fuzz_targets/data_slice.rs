// SPDX-License-Identifier: AGPL-3.0-only
/*
 * Copyright 2025-2026 Triton One Limited. All rights reserved.
 */

//! The encoding size check and `encode_ui_account` on any `dataSlice`: no panic, and the
//! encoded data is the slice that Agave returns.

#![no_main]

use arbitrary::Unstructured;
use cloudbreak_api::utils::encoding::check_account_data_len_for_encoding;
use cloudbreak_fuzz::offset;
use libfuzzer_sys::fuzz_target;
use solana_account::Account;
use solana_account_decoder::{UiAccountEncoding, UiDataSliceConfig, encode_ui_account};
use solana_pubkey::Pubkey;

fuzz_target!(|input: &[u8]| {
    let mut u = Unstructured::new(input);
    let (Ok(encoding), Ok(offset), Ok(length)) = (
        u.choose(&[
            UiAccountEncoding::Binary,
            UiAccountEncoding::Base58,
            UiAccountEncoding::Base64,
            UiAccountEncoding::Base64Zstd,
        ]),
        offset(&mut u),
        offset(&mut u),
    ) else {
        return;
    };
    let encoding = *encoding;
    let slice = UiDataSliceConfig { offset, length };
    let data = u.take_rest().to_vec();
    let pubkey = Pubkey::new_from_array([1; 32]);

    if check_account_data_len_for_encoding(encoding, Some(slice), data.len(), &pubkey).is_err() {
        return;
    }
    let start = offset.min(data.len());
    let expected = &data[start..start + length.min(data.len() - start)];
    let account = Account {
        data: data.clone(),
        ..Default::default()
    };
    let ui = encode_ui_account(&pubkey, &account, encoding, None, Some(slice));
    let decoded = ui.data.decode().expect("encoded data decodes");
    assert_eq!(decoded, expected);
});
