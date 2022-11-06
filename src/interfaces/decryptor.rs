use base64::DecodeError;
use std::io::{Read, Seek, Write};

// FIXME: better handling error messages.
//   e.g. https://boats.gitlab.io/failure/
#[derive(Debug, PartialEq, Eq)]
pub enum DecryptorError {
    IOError,
    NotImplementedError(String),
    QMCInvalidFooter(u32),
    QMCAndroidSTag,
    QMCAndroidQTagInvalid,
    StringEncodeError,
    Base64DecodeError(DecodeError),
    TEADecryptError,

    KGMInvalidKeySlotError(u32),
    KGMInvalidFileKey,
    KGMUnsupportedEncryptionType(u32),
    KGMv4ExpansionTableRequired,

    XimalayaCountNotFindImplementation,
}

pub trait Decryptor {
    fn check<R>(&self, from: &mut R) -> Result<(), DecryptorError>
    where
        R: Read + Seek;

    fn decrypt<R, W>(&self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write;
}
