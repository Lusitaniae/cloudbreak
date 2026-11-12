// SPDX-License-Identifier: AGPL-3.0-only
/*
 * Copyright 2025-2026 Triton One Limited. All rights reserved.
 */

//! Structured gPA filter inputs for the fuzz targets. Offsets favour the values where offset
//! arithmetic wraps or leaves the largest account.

use arbitrary::{Result, Unstructured};
use cloudbreak_core::modules::rpc_filter_type::{
    Comparator, MAX_ACCOUNT_DATA_LEN, Memcmp, MemcmpEncodedBytes, Operand, RpcFilterType, ValueCmp,
    ValueType,
};

pub fn offset(u: &mut Unstructured) -> Result<usize> {
    let near = |u: &mut Unstructured, base: usize| -> Result<usize> {
        Ok(base.wrapping_add(u.int_in_range(0..=64)?).wrapping_sub(32))
    };
    Ok(match u.int_in_range(0..=6)? {
        0 => u.int_in_range(0..=512)?,
        1 => near(u, MAX_ACCOUNT_DATA_LEN)?,
        2 => near(u, 1 << 31)?,
        3 => near(u, 1 << 32)?,
        4 => near(u, 1 << 63)?,
        5 => usize::MAX - u.int_in_range(0..=64)?,
        _ => u.arbitrary()?,
    })
}

pub fn value_type(u: &mut Unstructured) -> Result<ValueType> {
    Ok(match u.int_in_range(0..=4)? {
        0 => ValueType::U8,
        1 => ValueType::U16,
        2 => ValueType::U32,
        3 => ValueType::U64,
        _ => ValueType::U128,
    })
}

/// The width in bytes of a value of `value_type`.
pub fn value_size(value_type: &ValueType) -> usize {
    match value_type {
        ValueType::U8 => 1,
        ValueType::U16 => 2,
        ValueType::U32 => 4,
        ValueType::U64 => 8,
        ValueType::U128 => 16,
    }
}

fn comparator(u: &mut Unstructured) -> Result<Comparator> {
    Ok(match u.int_in_range(0..=5)? {
        0 => Comparator::Eq,
        1 => Comparator::Ne,
        2 => Comparator::Gt,
        3 => Comparator::Ge,
        4 => Comparator::Lt,
        _ => Comparator::Le,
    })
}

fn operand(u: &mut Unstructured) -> Result<Operand> {
    if u.ratio(3, 4)? {
        return Ok(Operand::Mem {
            offset: offset(u)?,
            value_type: value_type(u)?,
        });
    }
    Ok(Operand::Constant(if u.arbitrary()? {
        u.arbitrary::<u128>()?.to_string()
    } else {
        u.arbitrary()?
    }))
}

pub fn value_cmp(u: &mut Unstructured) -> Result<ValueCmp> {
    Ok(ValueCmp::new(operand(u)?, comparator(u)?, operand(u)?))
}

fn memcmp(u: &mut Unstructured) -> Result<Memcmp> {
    let offset = match u.int_in_range(0..=3)? {
        // The token account mint, owner, delegate tag and delegate offsets.
        0 => *u.choose(&[0, 32, 72, 76])?,
        _ => self::offset(u)?,
    };
    let len = u.int_in_range(0..=140)?;
    Ok(match u.int_in_range(0..=3)? {
        0 => Memcmp::new(offset, MemcmpEncodedBytes::Base58(u.arbitrary()?)),
        1 => Memcmp::new(offset, MemcmpEncodedBytes::Base64(u.arbitrary()?)),
        _ => Memcmp::new_raw_bytes(offset, u.bytes(len)?.to_vec()),
    })
}

pub fn filter(u: &mut Unstructured) -> Result<RpcFilterType> {
    Ok(match u.int_in_range(0..=3)? {
        0 => RpcFilterType::DataSize(u.arbitrary()?),
        1 => RpcFilterType::Memcmp(memcmp(u)?),
        2 => RpcFilterType::TokenAccountState,
        _ => RpcFilterType::ValueCmp(value_cmp(u)?),
    })
}

pub fn filters(u: &mut Unstructured) -> Result<Vec<RpcFilterType>> {
    (0..u.int_in_range(0..=6)?).map(|_| filter(u)).collect()
}
