use super::kgm_crypto::{KGMCrypto, KGMCryptoConfig};

// Transparent encryption.

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoType2 {
    key: Box<[u8]>,
}

impl KGMCrypto for KGMCryptoType2 {
    fn configure(&mut self, _config: &KGMCryptoConfig) {
        // noop
    }

    fn expand_slot_key(&mut self, slot_key: &[u8]) {
        self.key = slot_key.into();
    }

    fn expand_file_key(&mut self, _key: &[u8]) {
        // noop
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let key = &self.key;
        let mut offset = offset as usize;

        for item in buffer.iter_mut() {
            let mut temp = *item;
            temp ^= key[offset % key.len()];
            temp ^= temp << 4;
            *item = temp;

            offset += 1;
        }
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let key = &self.key;
        let mut offset = offset as usize;

        for item in buffer.iter_mut() {
            let mut temp = *item;
            temp ^= temp << 4;
            temp ^= key[offset % key.len()];
            *item = temp;

            offset += 1;
        }
    }
}
