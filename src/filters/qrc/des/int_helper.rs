pub(super) const fn make_u64(hi32: u32, lo32: u32) -> u64 {
    ((hi32 as u64) << 32) | (lo32 as u64)
}

pub(super) const fn swap_u64_side(value: u64) -> u64 {
    (value.wrapping_shr(32)) | (value.wrapping_shl(32))
}

pub(super) const fn u64_get_lo32(value: u64) -> u32 {
    value as u32
}

pub(super) const fn u64_get_hi32(value: u64) -> u32 {
    value.wrapping_shr(32) as u32
}

pub(super) const fn get_u64_by_shift_idx(value: u8) -> u64 {
    if cfg!(target_pointer_width = "64") {
        1u64.wrapping_shl(31u32.wrapping_sub(value as u32))
    } else {
        use super::data::U64_SHIFT_TABLE_CACHE;
        U64_SHIFT_TABLE_CACHE[value as usize]
    }
}

#[test]
fn test_get_u64_by_shift_idx() {
    use super::data::U64_SHIFT_TABLE_CACHE;

    for i in 0..32 {
        assert_eq!(get_u64_by_shift_idx(i), 1u64 << (31 - i));
        assert_eq!(get_u64_by_shift_idx(i + 32), 1u64 << (32 + 31 - i));
    }

    for i in 0..64 {
        assert_eq!(get_u64_by_shift_idx(i), U64_SHIFT_TABLE_CACHE[i as usize]);
    }
}

pub(super) fn map_bit(result: &mut u64, src: u64, check: u8, set: u8) {
    if get_u64_by_shift_idx(check) & src != 0 {
        *result |= get_u64_by_shift_idx(set)
    }
}

pub(super) fn map_u32_bits(src_value: u32, table: &[u8]) -> u32 {
    table
        .iter()
        .enumerate()
        .fold(0u64, |result, (i, &check_idx)| {
            let mut result = result;
            map_bit(&mut result, src_value as u64, check_idx, i as u8);
            result
        }) as u32
}

pub(super) fn map_u64(src_value: u64, table: &[u8]) -> u64 {
    assert!(table.len() % 2 == 0, "table.len() should be even");

    let (table_lo32, table_hi32) = table.split_at(table.len() / 2);

    let mut lo32 = 0u64;
    let mut hi32 = 0u64;

    for (i, (&idx_lo32, &idx_hi32)) in table_lo32.iter().zip(table_hi32).enumerate() {
        map_bit(&mut lo32, src_value, idx_lo32, i as u8);
        map_bit(&mut hi32, src_value, idx_hi32, i as u8);
    }

    make_u64(hi32 as u32, lo32 as u32)
}
