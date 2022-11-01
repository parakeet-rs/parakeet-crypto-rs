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

impl<const KEY_SIZE: usize> XmlyCrypto<KEY_SIZE> {
    pub fn new(content_key: &[u8; KEY_SIZE], scramble_table: &[usize; 1024]) -> Self {
        Self {
            content_key: *content_key,
            scramble_table: *scramble_table,
        }
    }

    fn decrypt_header(&self, &buffer: &[u8; 1024]) -> [u8; 1024] {
        let mut result = buffer;

        for (key_index, &i) in self.scramble_table.iter().enumerate() {
            result[i] = buffer[i] ^ self.content_key[key_index % self.content_key.len()]
        }

        result
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
        let mut header = [0u8; 1024];

        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;

        from.read_exact(&mut header)
            .or(Err(DecryptorError::IOError))?;

        let header = self.decrypt_header(&header);
        to.write_all(&header).or(Err(DecryptorError::IOError))?;

        std::io::copy(from, to).or(Err(DecryptorError::IOError))?;

        Ok(())
    }
}

// TODO: add a factory that detects which crypto to use, based on the file header + key provided.
pub type X2M = XmlyCrypto<4>;
pub type X3M = XmlyCrypto<32>;
