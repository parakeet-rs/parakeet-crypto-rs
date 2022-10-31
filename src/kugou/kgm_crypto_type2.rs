use super::kgm_crypto::KGMCrypto;

// Transparent encryption.

pub struct KGMCryptoType2 {
    key_slot_key: Vec<u8>,
}

impl KGMCryptoType2 {
    pub fn new() -> Self {
        Self {
            key_slot_key: vec![],
        }
    }
}

impl KGMCrypto for KGMCryptoType2 {
    fn expand_key_slot_key(&mut self, key_slot_key: &[u8]) {
        self.key_slot_key = key_slot_key.into();
    }

    fn expand_file_key(&mut self, _input: &[u8]) {
        // noop
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        todo!("not implemented")
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        todo!("not implemented")
    }
}
