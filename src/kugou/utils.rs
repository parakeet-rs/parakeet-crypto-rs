use crate::utils::md5;

pub fn md5_kugou<T: AsRef<[u8]>>(buffer: T) -> [u8; 16] {
    let digest = md5(buffer);
    let mut result = [0u8; 16];

    for i in (0..16).step_by(2) {
        result[i] = digest[14 - i];
        result[i + 1] = digest[14 - i + 1];
    }

    result
}

#[inline]
pub fn offset_to_xor_key(offset: u64) -> u8 {
    (offset as u32)
        .to_le_bytes()
        .iter()
        .fold(0, |acc, x| acc ^ x)
}
