use std::io::{self, Read};

use byteorder::{LittleEndian, ReadBytesExt};

pub struct KGMHeader {
    magic: [u8; 16],
    offset_to_data: u32,
    crypto_version: u32,
    key_slot: u32,
    decryptor_test_data: [u8; 16],
    file_key: [u8; 16],
}

impl KGMHeader {
    pub fn from_reader(mut reader: impl Read) -> io::Result<Self> {
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
