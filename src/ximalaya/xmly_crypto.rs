use std::io::{Read, Seek, SeekFrom, Write};

use crate::interfaces::decryptor::{Decryptor, DecryptorError};

#[derive(Debug, Clone, Copy)]
pub struct XimalayaCrypto {
    content_key: [u8; 32],
    scramble_table: [usize; 1024],
}

pub fn process_ximalaya_file<F, R, W>(
    from: &mut R,
    to: &mut W,
    handler: F,
) -> Result<(), std::io::Error>
where
    F: FnOnce(&[u8; 1024]) -> [u8; 1024],
    R: Read + Seek,
    W: Write,
{
    let mut header = [0u8; 1024];

    from.seek(SeekFrom::Start(0))?;
    from.read_exact(&mut header)?;

    let header = handler(&header);
    to.write_all(&header)?;

    std::io::copy(from, to)?;
    Ok(())
}

impl XimalayaCrypto {
    pub fn new(content_key: &[u8; 32], scramble_table: &[usize; 1024]) -> Self {
        Self {
            content_key: *content_key,
            scramble_table: *scramble_table,
        }
    }

    pub fn decrypt_header(&self, encrypted: &[u8; 1024]) -> [u8; 1024] {
        let mut decrypted = *encrypted;

        for (di, &ei) in self.scramble_table.iter().enumerate() {
            let key = self.content_key[di % self.content_key.len()];
            decrypted[di] = encrypted[ei] ^ key
        }

        decrypted
    }

    pub fn encrypt_header(&self, decrypted: &[u8; 1024]) -> [u8; 1024] {
        let mut encrypted = *decrypted;
        let reverse_scramble_table = self.scramble_table;

        for (di, &ei) in reverse_scramble_table.iter().enumerate() {
            let key = self.content_key[di % self.content_key.len()];
            encrypted[ei] = decrypted[di] ^ key
        }

        encrypted
    }

    pub fn encrypt<R, W>(&self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        process_ximalaya_file(from, to, |header| self.encrypt_header(header))
            .or(Err(DecryptorError::IOError))
    }
}

impl Decryptor for XimalayaCrypto {
    fn check<R>(&self, _from: &mut R) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
    {
        // TODO: Verify decrypted header after implementing AudioHeader checker.
        Ok(())
    }

    fn decrypt<R, W>(&self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        process_ximalaya_file(from, to, |header| self.decrypt_header(header))
            .or(Err(DecryptorError::IOError))
    }
}
