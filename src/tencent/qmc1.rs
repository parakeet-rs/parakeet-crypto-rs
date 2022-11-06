use crate::interfaces::decryptor::{Decryptor, DecryptorError};
use std::io::{Read, Seek, Write};

use super::{
    key_utils::init_qmc_static_map_table,
    qmc1_key_expansion::qmc_key_expansion_58_to_128,
    qmc_legacy_block::{qmc_legacy_decrypt_stream, QMCLegacyBlockDecryptor},
};

/// QMC v1 decryptor
pub struct QMC1 {
    table: [u8; 0x8000],
}

impl QMC1 {
    pub fn new(key: &[u8]) -> Self {
        match key.len() {
            58 => Self::new_key58(key.try_into().unwrap()),
            128 => Self::new_key128(key.try_into().unwrap()),
            _ => panic!("key size should be 58 or 128."),
        }
    }

    pub fn new_key128(key: &[u8; 128]) -> Self {
        let mut table = [0u8; 0x8000];
        init_qmc_static_map_table(&mut table, key, |i, key| key[i as usize]);

        Self { table }
    }

    pub fn new_key58(key58: &[u8; 58]) -> Self {
        let key128 = qmc_key_expansion_58_to_128(key58);
        Self::new_key128(&key128)
    }
}

impl QMCLegacyBlockDecryptor for QMC1 {
    /// Decrypt a block.
    /// `offset` is the offset of the block (0~0x7fff)
    #[inline]
    fn decrypt_block(&self, block: &mut [u8], offset: usize) {
        for (i, value) in block.iter_mut().enumerate() {
            *value ^= self.table[i + offset];
        }
    }
}

impl Decryptor for QMC1 {
    fn check<R>(&self, _from: &mut R) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
    {
        // TODO: Check for header after decrypting?

        Ok(())
    }

    fn decrypt<R, W>(&self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        qmc_legacy_decrypt_stream(0, self, from, to)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::PathBuf,
    };

    use super::*;

    const TEST_KEY58: [u8; 58] = [
        0xFF, 0xFE, //
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, //
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, //
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, //
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, //
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, //
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, //
    ];

    const TEST_KEY128: [u8; 128] = [
        0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0xfe, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, //
        0xff, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, //
        0xfe, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, //
        0xff, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, //
        0xfe, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, //
        0xff, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, //
        0xfe, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, //
        0xff, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, //
        0xfe, 0x31, 0x30, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, //
        0xff, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, //
        0xfe, 0x23, 0x22, 0x21, 0x20, 0x1f, 0x1e, 0x1d, //
        0xff, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, //
        0xfe, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, //
        0xff, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, //
        0xfe, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, //
    ];

    fn run_test_qmc1(key: &[u8]) {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path_encrypted = d.join("sample/test_qmc1.qmcogg");
        let path_source = d.join("sample/test_121529_32kbps.ogg");
        let mut decrypted_content = Vec::new();

        let qmc1 = super::QMC1::new(key);

        let mut file_encrypted = File::open(path_encrypted).unwrap();
        let source_content = fs::read(path_source.as_path()).unwrap();
        qmc1.decrypt(&mut file_encrypted, &mut decrypted_content)
            .unwrap();

        assert_eq!(source_content, decrypted_content, "mismatched content");
    }

    #[test]
    fn test_qmc1_key128() {
        run_test_qmc1(&TEST_KEY128);
    }

    #[test]
    fn test_qmc1_key58() {
        run_test_qmc1(&TEST_KEY58);
    }
}
