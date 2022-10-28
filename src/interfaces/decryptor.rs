use std::io::{Read, Seek, Write};

pub trait SeekReadable: Seek + Read {}

pub enum DecryptorError {
    IOError(std::io::Error),
    NotImplementedError(String),
    QMCInvalidFooter(u32),
    QMCAndroidSTag,
}

pub trait Decryptor {
    fn check(&self, from: &mut dyn SeekReadable) -> Result<bool, DecryptorError>;
    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn Write,
    ) -> Result<(), DecryptorError>;
}
