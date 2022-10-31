use std::io::Cursor;

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
    pub fn from_reader(reader: &mut dyn SeekReadable) -> std::io::Result<Self> {
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

    pub fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        let mut stream = vec![];
        stream.extend(bytes);
        Self::from_reader(&mut Cursor::new(stream))
    }

    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut result: Vec<u8> = vec![];
        result.extend(self.magic);
        result.extend(self.offset_to_data.to_le_bytes());
        result.extend(self.crypto_version.to_le_bytes());
        result.extend(self.key_slot.to_le_bytes());
        result.extend(self.decryptor_test_data);
        result.extend(self.file_key);

        debug_assert!(self.offset_to_data as usize >= result.len());
        result.resize(self.offset_to_data as usize, 0);

        result.into()
    }
}
