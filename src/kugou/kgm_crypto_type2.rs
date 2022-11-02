use crate::interfaces::decryptor::DecryptorError;

use super::kgm_crypto::{KGMCrypto, KGMCryptoConfig};

// Transparent encryption.

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoType2 {
    key: Box<[u8]>,
}

impl KGMCrypto for KGMCryptoType2 {
    fn configure(&mut self, _config: &KGMCryptoConfig) -> Result<(), DecryptorError> {
        Ok(())
    }

    fn expand_slot_key(&mut self, slot_key: &[u8]) {
        self.key = slot_key.into();
    }

    fn expand_file_key(&mut self, _key: &[u8]) {
        // noop
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset as usize;

        let key = &self.key;

        for item in buffer.iter_mut() {
            let key_index = offset % key.len();

            let mut temp = *item;
            temp ^= key[key_index];
            temp ^= temp << 4;
            *item = temp;

            offset += 1;
        }
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset as usize;

        let key = &self.key;

        for item in buffer.iter_mut() {
            let key_index = offset % key.len();

            let mut temp = *item;
            temp ^= temp << 4;
            temp ^= key[key_index];
            *item = temp;

            offset += 1;
        }
    }
}
