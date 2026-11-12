// SPDX-License-Identifier: AGPL-3.0-only
/*
 * Copyright 2025-2026 Triton One Limited. All rights reserved.
 */

//! `SqlFilters::build` and the query-tracker `CREATE INDEX` on any filters: no panic, every
//! placeholder is bound, every byte range stays inside the largest account, and the SQL parses.

#![no_main]

use arbitrary::Unstructured;
use cloudbreak_api::utils::sql_filters::SqlFilters;
use cloudbreak_core::modules::index_identity::IndexIdentity;
use cloudbreak_core::modules::rpc_filter_type::{MAX_ACCOUNT_DATA_LEN, RpcProgramAccountsConfig};
use cloudbreak_core::utils::token::{LEGACY_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID};
use cloudbreak_fuzz::filters;
use libfuzzer_sys::fuzz_target;
use solana_pubkey::Pubkey;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// The numbers that follow each `keyword` in `sql`, such as the `n` of every `$n`.
fn numbers_after<'a>(sql: &'a str, keyword: &'a str) -> impl Iterator<Item = u128> + 'a {
    sql.match_indices(keyword).filter_map(move |(at, _)| {
        let digits: String = sql[at + keyword.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    })
}

/// Every `{open}start{sep}length` byte range in `sql`.
fn ranges(sql: &str, open: &str, sep: &str) -> Vec<(u128, u128)> {
    let number = |s: &str| -> Option<(u128, usize)> {
        let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
        Some((digits.parse().ok()?, digits.len()))
    };
    sql.match_indices(open)
        .filter_map(|(at, _)| {
            let rest = &sql[at + open.len()..];
            let (start, used) = number(rest)?;
            let (length, _) = number(rest[used..].strip_prefix(sep)?)?;
            Some((start, length))
        })
        .collect()
}

/// Panics unless the byte ranges in `sql` fit the largest account and the SQL parses.
fn check_sql(sql: &str, open: &str, sep: &str) {
    for (start, length) in ranges(sql, open, sep) {
        assert!(start >= 1, "range starts at {start}: {sql}");
        assert!(
            start - 1 + length <= MAX_ACCOUNT_DATA_LEN as u128,
            "range {start}+{length} leaves the account: {sql}"
        );
    }
    if let Err(e) = Parser::parse_sql(&PostgreSqlDialect {}, sql) {
        panic!("{e}: {sql}");
    }
}

fuzz_target!(|input: &[u8]| {
    let mut u = Unstructured::new(input);
    let Ok(filters) = filters(&mut u) else {
        return;
    };
    let program = match u.int_in_range(0..=2).unwrap_or(0) {
        0 => LEGACY_TOKEN_PROGRAM_ID,
        1 => TOKEN_2022_PROGRAM_ID,
        _ => Pubkey::new_from_array([7; 32]),
    };

    if let Ok(sql) = SqlFilters::build(&program, &filters, "gpa") {
        for n in numbers_after(&sql.accounts, "$").chain(numbers_after(&sql.snapshot, "$")) {
            assert!(
                (1..=sql.params.len() as u128).contains(&n),
                "${n} with {} params: {}",
                sql.params.len(),
                sql.accounts
            );
        }
        for (table, clauses) in [
            ("accounts", &sql.accounts),
            ("snapshot_accounts", &sql.snapshot),
        ] {
            check_sql(
                &format!("SELECT 1 FROM {table} WHERE TRUE {clauses}"),
                "data FROM ",
                " FOR ",
            );
        }
    }

    let config = RpcProgramAccountsConfig {
        filters: Some(filters),
        ..Default::default()
    };
    if let Some(identity) = IndexIdentity::parse(program, Some(&config)) {
        check_sql(
            &identity.create_index_sql("accounts"),
            "substring(data, ",
            ", ",
        );
    }
});
