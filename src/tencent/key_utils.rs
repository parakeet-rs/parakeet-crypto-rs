use std::ops::{Div, Mul};

/// Used by the "QMC2 footer parser", used to derive the file key.
pub fn make_simple_key(seed: u8, size: usize) -> Box<[u8]> {
    let seed = seed as f32;
    let mut result = vec![0u8; size].into_boxed_slice();

    for (i, v) in result.iter_mut().enumerate() {
        let i = i as f32;
        let angle = seed + i * 0.1;
        *v = angle.tan().abs().mul(100.0) as u8;
    }

    result
}

pub fn calculate_key_hash(key: &[u8]) -> u32 {
    let mut hash = 1u32;
    for &v in key.iter() {
        if v == 0 {
            continue;
        }

        let next_hash = hash.wrapping_mul(v as u32);
        if next_hash == 0 || next_hash <= hash {
            break;
        }

        hash = next_hash;
    }

    hash
}

pub fn get_segment_key(key_hash: u64, id: u64, seed: u64) -> usize {
    if seed == 0 {
        0
    } else {
        100u64.wrapping_mul(key_hash).div(seed.wrapping_mul(id + 1)) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_key() {
        let expected: &[u8] = b"\x33\x41\x50\x62\x78\x94\xba\xf1";
        let key = make_simple_key(123, 8);
        assert_eq!(&key[..], expected)
    }
}
