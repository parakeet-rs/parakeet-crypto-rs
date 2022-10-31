use std::io::SeekFrom;

use crate::interfaces::decryptor::{Decryptor, DecryptorError, SeekReadable};

use super::utils::md5_kugou;

pub struct KGM {
    slot_key1: [u8; 4],
}

impl KGM {
    pub fn new(slot_key1: [u8; 4]) -> Self {
        Self { slot_key1 }
    }

    fn get_slot_key(&self, key_index: usize) -> Box<[u8]> {
        match key_index {
            1 => Box::from(&self.slot_key1 as &[u8]),
            _ => Box::from(&[0u8; 0] as &[u8]),
        }
    }
}

impl Decryptor for KGM {
    fn check(&self, from: &mut dyn SeekReadable) -> Result<bool, DecryptorError> {
        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;

        let mut file_header = [0u8; 0x40];
        from.read_exact(&mut file_header)
            .or(Err(DecryptorError::IOError))?;

        Ok(false)
    }
    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
    ) -> Result<(), DecryptorError> {
        Ok(())
    }
}
