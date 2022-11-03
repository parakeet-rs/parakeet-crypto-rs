use std::io::SeekFrom;

use crate::interfaces::decryptor::{Decryptor, DecryptorError, SeekReadable};

/// Why "generic" instead of a vector etc:
///   The key size is known to be the power of twos (4 & 32).
///   By using a fixed size, that is known at compile time,
///   the "mod" opcode can be optimised as "bitwise and" instead.
///   (Performance reasons)
#[derive(Debug, Clone, Copy)]
pub struct XmlyCrypto<const KEY_SIZE: usize> {
    content_key: [u8; KEY_SIZE],
    scramble_table: [usize; 1024],
}

pub trait XmlyCryptoImpl: Decryptor {
    fn decrypt_header(&self, encrypted: &[u8; 1024]) -> [u8; 1024];
    fn encrypt_header(&self, encrypted: &[u8; 1024]) -> [u8; 1024];

    fn encrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
    ) -> Result<(), DecryptorError>;
}

impl<const KEY_SIZE: usize> XmlyCryptoImpl for XmlyCrypto<KEY_SIZE> {
    fn decrypt_header(&self, encrypted: &[u8; 1024]) -> [u8; 1024] {
        let mut decrypted = *encrypted;

        for (di, &ei) in self.scramble_table.iter().enumerate() {
            let key = self.content_key[di % self.content_key.len()];
            decrypted[di] = encrypted[ei] ^ key
        }

        decrypted
    }

    fn encrypt_header(&self, decrypted: &[u8; 1024]) -> [u8; 1024] {
        let mut encrypted = *decrypted;
        let reverse_scramble_table = self.scramble_table;

        for (di, &ei) in reverse_scramble_table.iter().enumerate() {
            let key = self.content_key[di % self.content_key.len()];
            encrypted[ei] = decrypted[di] ^ key
        }

        encrypted
    }

    fn encrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
    ) -> Result<(), DecryptorError> {
        self.handle_file(from, to, |header| self.encrypt_header(header))
            .or(Err(DecryptorError::IOError))
    }
}

impl<const KEY_SIZE: usize> XmlyCrypto<KEY_SIZE> {
    pub fn new(content_key: &[u8; KEY_SIZE], scramble_table: &[usize; 1024]) -> Self {
        Self {
            content_key: *content_key,
            scramble_table: *scramble_table,
        }
    }

    fn handle_file<F>(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
        handler: F,
    ) -> Result<(), std::io::Error>
    where
        F: FnOnce(&[u8; 1024]) -> [u8; 1024],
    {
        let mut header = [0u8; 1024];

        from.seek(SeekFrom::Start(0))?;

        from.read_exact(&mut header)?;

        let header = handler(&header);
        to.write_all(&header)?;

        std::io::copy(from, to)?;

        Ok(())
    }
}

impl<const KEY_SIZE: usize> Decryptor for XmlyCrypto<KEY_SIZE> {
    fn check(&self, _from: &mut dyn SeekReadable) -> Result<bool, DecryptorError> {
        // TODO: Verify decrypted header after implementing AudioHeader checker.
        Ok(true)
    }

    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
    ) -> Result<(), DecryptorError> {
        self.handle_file(from, to, |header| self.decrypt_header(header))
            .or(Err(DecryptorError::IOError))
    }
}

pub type X2M = XmlyCrypto<4>;
pub type X3M = XmlyCrypto<32>;

pub fn new_from_key(
    key: &[u8],
    scramble_table: &[usize; 1024],
) -> Result<Box<dyn XmlyCryptoImpl>, DecryptorError> {
    let decryptor: Box<dyn XmlyCryptoImpl> = match key.len() {
        4 => {
            let mut buffer = [0u8; 4];
            buffer.copy_from_slice(key);
            Box::from(X2M::new(&buffer, scramble_table))
        }

        32 => {
            let mut buffer = [0u8; 32];
            buffer.copy_from_slice(key);
            Box::from(X3M::new(&buffer, scramble_table))
        }

        _ => return Err(DecryptorError::XimalayaCountNotFindImplementation),
    };

    Ok(decryptor)
}
