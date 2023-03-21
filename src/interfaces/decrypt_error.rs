use base64::DecodeError;
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecryptorError {
    #[error("output buffer is too small")]
    OutputBufferTooSmall,
    #[error("output buffer is too small, suggested size = {0}")]
    OutputBufferTooSmallWithHint(usize),
    #[error("input buffer size does not match output buffer size")]
    InputOutputBufferLenMismatch,

    #[error("io error, {0}")]
    IOError(#[from] std::io::Error),
    #[error("{0} not implement")]
    NotImplementedError(String),
    #[error("QMC Static Cipher init failed - is key length correct?")]
    QMCv1InitFailed,
    #[error("QMC parse error - footer magic number: {}", hex::encode(.0))]
    QMCInvalidFooter(Box<[u8]>),
    #[error("QMC init error - tail detection buffer too small")]
    QMCTailBufferTooSmall,
    #[error("Parsing 'STag' file failed.")]
    QMCAndroidSTag,
    #[error("Parsing 'QTag' file failed.")]
    QMCAndroidQTagInvalid,
    #[error("string encode error, {0}")]
    StringEncodeError(#[from] Utf8Error),
    #[error("base64 decode error, {0}")]
    Base64DecodeError(#[from] DecodeError),
    #[error("TEA key error (is your key correct?)")]
    TEADecryptError,
    #[error("Input stream does not have a block size of 8.")]
    QrcDesblockAlignment,

    #[error("invalid kugou key slot: {0}")]
    KGMInvalidKeySlotError(u32),
    #[error("invalid kugou file key")]
    KGMInvalidFileKey,
    #[error("unsupported kgm magic header")]
    KGMUnsupportedMagic,
    #[error("unsupport kugou encryption type: {0}")]
    KGMUnsupportedEncryptionType(u32),
    #[error("both kugou v4 expansion tables are required.")]
    KGMv4ExpansionTableRequired,

    #[error("Ximalaya cound not find implementation")]
    XimalayaCountNotFindImplementation,
}
