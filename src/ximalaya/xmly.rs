use std::io::{Read, Seek, Write};

use crate::interfaces::decryptor::{Decryptor, DecryptorError};

use super::xmly_crypto::{process_ximalaya_file, XimalayaCrypto};

#[derive(Debug, Clone, Copy)]
pub struct XimalayaDecryptor {
    crypto: XimalayaCrypto,
}

impl XimalayaDecryptor {
    pub fn new(content_key: &[u8; 32], scramble_table: &[usize; 1024]) -> Self {
        Self {
            crypto: XimalayaCrypto::new(content_key, scramble_table),
        }
    }
}

impl Decryptor for XimalayaDecryptor {
    fn check<R>(&self, _from: &mut R) -> Result<bool, DecryptorError>
    where
        R: Read + Seek,
    {
        // TODO: Verify decrypted header after implementing AudioHeader checker.
        Ok(true)
    }

    fn decrypt<R, W>(&self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        process_ximalaya_file(from, to, |header| self.crypto.decrypt_header(header))
            .or(Err(DecryptorError::IOError))
    }
}

pub fn new_from_key(
    key: &[u8],
    scramble_table: &[usize; 1024],
) -> Result<Box<dyn Decryptor>, DecryptorError> {
    // FIXME: This type is broken.
    let mut key_final = [0u8; 32];

    match key.len() {
        4 => {
            for i in (0..32).step_by(4) {
                &key_final[i..i + 4].copy_from_slice(key);
            }
        }

        32 => {
            key_final.copy_from_slice(key);
        }

        _ => return Err(DecryptorError::XimalayaCountNotFindImplementation),
    };

    let decryptor: Box<dyn Decryptor> =
        Box::from(XimalayaDecryptor::new(&key_final, scramble_table));
    Ok(decryptor)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::PathBuf,
    };

    fn test_xmly_file(xmly_type: &str) {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path_encrypted = d.join(format!("sample/test_xmly.{}", xmly_type));
        let path_source = d.join("sample/test_121529_32kbps.ogg");
        let path_content_key = d.join(format!("sample/test_{}_key.bin", xmly_type));
        let path_scramble_table = d.join("sample/test_xmly_scramble_table.bin");

        let mut decrypted_content = Vec::new();

        let mut file_encrypted = File::open(path_encrypted).unwrap();
        let source_content = fs::read(path_source.as_path()).unwrap();
        let content_key = fs::read(path_content_key.as_path()).unwrap();
        let scramble_table_bin = fs::read(path_scramble_table.as_path()).unwrap();

        let mut scramble_table = [0usize; 1024];
        for (i, item) in scramble_table.iter_mut().enumerate() {
            let mut buffer = [0u8; 2];
            buffer.copy_from_slice(&scramble_table_bin[i * 2..i * 2 + 2]);
            *item = u16::from_le_bytes(buffer) as usize;
        }

        let decryptor = super::new_from_key(&content_key, &scramble_table).unwrap();
        decryptor
            .decrypt(&mut file_encrypted, &mut decrypted_content)
            .unwrap();

        assert_eq!(source_content, decrypted_content, "mismatched content");
    }

    #[test]
    fn test_x2m() {
        test_xmly_file("x2m");
    }

    #[test]
    fn test_x3m() {
        test_xmly_file("x3m");
    }
}
