use std::{collections::HashMap, io::SeekFrom};

use crate::interfaces::decryptor::{Decryptor, DecryptorError, SeekReadable};

use super::{kgm_crypto_factory::create_kgm_crypto, kgm_header::KGMHeader};

pub struct KGM {
    slot_keys: HashMap<u32, Box<[u8]>>,
}

impl KGM {
    pub fn new(slot_keys: &HashMap<u32, Box<[u8]>>) -> Self {
        Self {
            slot_keys: slot_keys.clone(),
        }
    }
}

impl Decryptor for KGM {
    fn check(&self, from: &mut dyn SeekReadable) -> Result<bool, DecryptorError> {
        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;

        let header = KGMHeader::from_reader(from).or(Err(DecryptorError::IOError))?;

        create_kgm_crypto(&header, &self.slot_keys).and(Ok(true))
    }

    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
    ) -> Result<(), DecryptorError> {
        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;

        let header = KGMHeader::from_reader(from).or(Err(DecryptorError::IOError))?;
        let mut decryptor = create_kgm_crypto(&header, &self.slot_keys)?;

        let mut bytes_left = from
            .seek(SeekFrom::End(0))
            .or(Err(DecryptorError::IOError))?
            - header.offset_to_data as u64;

        from.seek(SeekFrom::Start(header.offset_to_data as u64))
            .or(Err(DecryptorError::IOError))?;

        let mut offset = 0;
        let mut buffer = [0u8; 0x1000];
        while bytes_left > 0 {
            let bytes_read = from.read(&mut buffer).or(Err(DecryptorError::IOError))?;
            decryptor.decrypt(offset, &mut buffer[..bytes_read]);
            to.write_all(&buffer[..bytes_read])
                .or(Err(DecryptorError::IOError))?;
            offset += bytes_read as u64;
            bytes_left -= bytes_read as u64;
        }

        Ok(())
    }
}
