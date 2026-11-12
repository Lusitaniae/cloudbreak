# Fuzz targets

cargo-fuzz targets for the gPA filter and request parsing code. Build them with overflow checks on (`-a`), so that a wrapped offset fails at the add.

| Target | Checks |
|---|---|
| `value_cmp` | `ValueCmp::values_match` does not panic, and an operand outside the account data does not match. |
| `sql_filters` | `SqlFilters::build` and the query-tracker `CREATE INDEX` do not panic, every `$n` is bound, every byte range stays inside 10 MiB, and the SQL parses as PostgreSQL. |
| `program_accounts_config` | The vendored `RpcProgramAccountsConfig` accepts and rejects the same JSON as Agave's, and each filter passes `verify` in both. |
| `data_slice` | The encoding size check and `encode_ui_account` do not panic, and the encoded data is the slice that Agave returns. |

```bash
cargo install cargo-fuzz
cargo +nightly fuzz build -s none -a
cargo +nightly fuzz run -s none -a sql_filters -- -max_total_time=600 -fork=3
cargo +nightly fuzz run -s none -a program_accounts_config -- -dict=fuzz/config.dict -max_total_time=600
```

Seed `fuzz/corpus/program_accounts_config/` with a few gPA config JSON objects. The other targets need no seeds.
