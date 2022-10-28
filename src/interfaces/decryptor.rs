use base64::DecodeError;
use std::io::{Read, Seek, Write};

pub trait SeekReadable: Seek + Read {}

impl SeekReadable for std::fs::File {}
impl SeekReadable for std::io::Cursor<Vec<u8>> {}
impl SeekReadable for std::io::Cursor<&[u8]> {}

#[derive(Debug, PartialEq)]
pub enum DecryptorError {
    IOError,
    NotImplementedError(String),
    QMCInvalidFooter(u32),
    QMCAndroidSTag,
    QMCAndroidQTagInvalid,
    StringEncodeError,
    Base64DecodeError(DecodeError),
    TEADecryptError,
}

pub trait Decryptor {
    fn check(&self, from: &mut dyn SeekReadable) -> Result<bool, DecryptorError>;
    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn Write,
    ) -> Result<(), DecryptorError>;
}
