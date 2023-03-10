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
    1u64.wrapping_shl(31u32.wrapping_sub(value as u32))
}

#[test]
fn test_get_u64_by_shift_idx() {
    for i in 0..32 {
        assert_eq!(get_u64_by_shift_idx(i), 1u64 << (31 - i));
        assert_eq!(get_u64_by_shift_idx(i + 32), 1u64 << (32 + 31 - i));
    }
}

pub(super) const fn map_bit_u32(data: u32, check_idx: u8, set_bit_idx: u8) -> u32 {
    map_bit_u64_to_u32(data as u64, check_idx, set_bit_idx)
}

pub(super) const fn map_bit_u64_to_u32(data: u64, check_idx: u8, set_bit_idx: u8) -> u32 {
    if get_u64_by_shift_idx(check_idx) & data != 0 {
        get_u64_by_shift_idx(set_bit_idx) as u32 // take lo32
    } else {
        0
    }
}

pub(super) fn map_u32_bits(src_value: u32, table: &[u8]) -> u32 {
    table
        .iter()
        .enumerate()
        .fold(0u32, |result, (i, &check_idx)| {
            result | map_bit_u32(src_value, check_idx, i as u8)
        })
}

pub(super) fn map_2_u32_bits_to_u64(
    src_lo32: u32,
    table_lo32: &[u8],
    src_hi32: u32,
    table_hi32: &[u8],
) -> u64 {
    assert_eq!(table_hi32.len(), table_lo32.len());

    let mut lo32 = 0;
    let mut hi32 = 0;

    for i in 0..table_hi32.len() {
        lo32 |= map_bit_u32(src_lo32, table_lo32[i], i as u8);
        hi32 |= map_bit_u32(src_hi32, table_hi32[i], i as u8);
    }

    make_u64(hi32, lo32)
}

pub(super) fn map_u64_to_u32_bits(src_value: u64, table: &[u8]) -> u32 {
    table
        .iter()
        .enumerate()
        .fold(0u32, |result, (i, &check_idx)| {
            result | map_bit_u64_to_u32(src_value, check_idx, i as u8)
        })
}

pub(super) fn map_u64_bits(value: u64, table: &[u8; 64]) -> u64 {
    let (table_lo32, table_hi32) = table.split_at(32);
    let lo32 = map_u64_to_u32_bits(value, table_lo32);
    let hi32 = map_u64_to_u32_bits(value, table_hi32);
    make_u64(hi32, lo32)
}
