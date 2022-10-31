use super::{kgm_crypto::KGMCrypto, utils::md5_kugou};

pub struct KGMCryptoType3 {
    key1: [u8; 16],
    key2: [u8; 17],
}

impl KGMCryptoType3 {
    pub fn new() -> Self {
        Self {
            key1: [0; 16],
            key2: [0; 17],
        }
    }
}

impl KGMCrypto for KGMCryptoType3 {
    fn expand_key_slot_key(&mut self, input: &[u8]) {
        self.key1 = md5_kugou(&input);
    }

    fn expand_file_key(&mut self, input: &[u8]) {
        self.key2[..16].copy_from_slice(&md5_kugou(&input));
        self.key2[16] = 0x6b;
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let key1 = self.key1;
        let key2 = self.key2;
        let mut offset = offset;

        for item in buffer.iter_mut() {
            let off_usize = offset as usize;
            let off_bytes = (offset as u32).to_le_bytes();

            let mut temp = *item;
            temp ^= key2[off_usize % key2.len()];
            temp ^= temp << 4;
            temp ^= key1[off_usize % key1.len()];
            temp ^= off_bytes[0] ^ off_bytes[1] ^ off_bytes[2] ^ off_bytes[3];
            *item = temp;

            offset += 1;
        }
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let key1 = self.key1;
        let key2 = self.key2;
        let mut offset = offset;

        for item in buffer.iter_mut() {
            let off_usize = offset as usize;
            let off_bytes = (offset as u32).to_le_bytes();

            let mut temp = *item;
            temp ^= off_bytes[0] ^ off_bytes[1] ^ off_bytes[2] ^ off_bytes[3];
            temp ^= key1[off_usize % key1.len()];
            temp ^= temp << 4;
            temp ^= key2[off_usize % key2.len()];
            *item = temp;

            offset += 1;
        }
    }
}
