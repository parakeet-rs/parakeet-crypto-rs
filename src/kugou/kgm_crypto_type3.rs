use super::{
    kgm_crypto::{KGMCrypto, KGMCryptoConfig},
    utils::{md5_kugou, offset_to_xor_key},
};

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoType3 {
    slot_key: [u8; 16],
    file_key: [u8; 17],
}

impl KGMCrypto for KGMCryptoType3 {
    fn configure(&mut self, _config: &KGMCryptoConfig) {
        // noop
    }

    fn expand_slot_key(&mut self, key: &[u8]) {
        self.slot_key = md5_kugou(&key);
    }

    fn expand_file_key(&mut self, key: &[u8]) {
        self.file_key[..16].copy_from_slice(&md5_kugou(&key));
        self.file_key[16] = 0x6b;
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;

        let key1 = self.slot_key;
        let key2 = self.file_key;

        let key1_len = self.slot_key.len();
        let key2_len = self.file_key.len();

        for item in buffer.iter_mut() {
            // XOR all bytes of a "u32" integer.
            let offset_key = offset_to_xor_key(offset);

            let offset_usize = offset as usize;
            let key1_index = offset_usize % key1_len;
            let key2_index = offset_usize % key2_len;

            let mut temp = *item;
            temp ^= key2[key2_index];
            temp ^= temp << 4;
            temp ^= key1[key1_index];
            temp ^= offset_key;
            *item = temp;

            offset += 1;
        }
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;

        let key1 = self.slot_key;
        let key2 = self.file_key;

        let key1_len = self.slot_key.len();
        let key2_len = self.file_key.len();

        for item in buffer.iter_mut() {
            // XOR all bytes of a "u32" integer.
            let offset_key = offset_to_xor_key(offset);

            let offset_usize = offset as usize;
            let key1_index = offset_usize % key1_len;
            let key2_index = offset_usize % key2_len;

            let mut temp = *item;
            temp ^= offset_key;
            temp ^= key1[key1_index];
            temp ^= temp << 4;
            temp ^= key2[key2_index];
            *item = temp;

            offset += 1;
        }
    }
}
