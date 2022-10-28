use std::ops::Mul;

pub fn make_key(seed: u8, size: usize) -> Box<[u8]> {
    let seed = seed as f32;
    let mut result = vec![0u8; size].into_boxed_slice();

    for (i, v) in result.iter_mut().enumerate() {
        let i = i as f32;
        let angle = seed + i * 0.1;
        *v = angle.tan().abs().mul(100.0) as u8;
    }

    result
}
