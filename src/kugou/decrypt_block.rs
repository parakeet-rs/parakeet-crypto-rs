pub fn decrypt_block(offset: u64, buffer: &mut [u8], key1: &[u8], key2: &[u8]) {
    let mut offset = offset;

    for item in buffer.iter_mut() {
        let off_usize = offset as usize;
        let off_bytes = (offset as u32).to_le_bytes();

        let temp = *item ^ key2[off_usize % key2.len()];
        let temp = temp ^ (temp << 4) ^ key1[off_usize % key1.len()];
        let temp = temp ^ off_bytes[0] ^ off_bytes[1] ^ off_bytes[2] ^ off_bytes[3];
        *item = temp;

        offset += 1;
    }
}
