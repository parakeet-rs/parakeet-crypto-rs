use super::{key_derive::KGMDecryptor, utils::md5_kugou};

struct KeyDeriveType3 {
    key1: [u8; 16],
    key2: [u8; 17],
}

impl KGMDecryptor for KeyDeriveType3 {
    fn expand_key_slot_key(&mut self, input: &[u8]) {
        self.key1 = md5_kugou(&input);
    }

    fn expand_file_key(&mut self, input: &[u8]) {
        self.key2[..16].copy_from_slice(&md5_kugou(&input));
        self.key2[16] = 0x6b;
    }

    fn decrypt_block(&mut self, offset: u64, buffer: &mut [u8]) {
        let key1 = self.key1;
        let key2 = self.key2;
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
}
