use std::io::{self, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::interfaces::decryptor::SeekReadable;

pub struct KGMHeader {
    pub magic: [u8; 16],
    pub offset_to_data: u32,
    pub crypto_version: u32,
    pub key_slot: u32,
    pub decryptor_test_data: [u8; 16],
    pub file_key: [u8; 16],
}

impl KGMHeader {
    // FIXME: Why can't I use "dyn Read" here?
    pub fn from_reader(reader: &mut dyn SeekReadable) -> io::Result<Self> {
        let mut magic = [0u8; 16];
        let mut decryptor_test_data = [0u8; 16];
        let mut file_key = [0u8; 16];

        reader.read_exact(&mut magic)?;
        let offset_to_data = reader.read_u32::<LittleEndian>()?;
        let crypto_version = reader.read_u32::<LittleEndian>()?;
        let key_slot = reader.read_u32::<LittleEndian>()?;
        reader.read_exact(&mut decryptor_test_data)?;
        reader.read_exact(&mut file_key)?;

        Ok(Self {
            magic,
            offset_to_data,
            crypto_version,
            key_slot,
            decryptor_test_data,
            file_key,
        })
    }
}
