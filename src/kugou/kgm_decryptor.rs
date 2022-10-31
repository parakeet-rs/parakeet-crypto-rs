use std::io::SeekFrom;

use crate::interfaces::decryptor::{Decryptor, DecryptorError, SeekReadable};

use super::utils::md5_kugou;

pub struct KGM {
    slot_key1: [u8; 16],
}

impl KGM {
    pub fn new(slot_key1: [u8; 4]) -> Self {
        let slot_key1 = md5_kugou(&slot_key1);
        Self { slot_key1 }
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
