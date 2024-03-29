use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use argh::FromArgs;

use parakeet_crypto::crypto::tencent;
use parakeet_crypto::crypto::tencent::{ekey, QMCv2};

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::utils::{decrypt_file_stream, QMCKeyType};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath},
};

/// Handle QMCv2 File.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "qmc2")]
pub struct Options {
    /// encryption key
    #[argh(option, short = 'k')]
    key: Option<CliBinaryContent>,

    /// key type, default to "ekey".
    /// when absent, this will attempt to extract from tail.
    #[argh(option, short = 't', default = "QMCKeyType::EKey")]
    key_type: QMCKeyType,

    /// number of bytes to trim off the tail.
    /// when key is provided, this will default to 0.
    /// when key is absent, this will auto-detect from tail.
    #[argh(option)]
    tail_trim: Option<i64>,

    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output_file: CliFilePath,
}

const TAIL_BUF_LEN: usize = 1024;

pub fn handle(args: Options) -> Result<(), ParakeetCliError> {
    let log = CliLogger::new("QMCv2");

    let mut src = File::open(args.input_file.path).map_err(ParakeetCliError::SourceIoError)?;
    let mut dst =
        File::create(args.output_file.path).map_err(ParakeetCliError::DestinationIoError)?;

    // Parse input file tail first
    let mut tail_buf = vec![0u8; TAIL_BUF_LEN].into_boxed_slice();
    src.seek(SeekFrom::End(-(TAIL_BUF_LEN as i64)))
        .map_err(ParakeetCliError::SourceIoError)?;
    src.read(&mut tail_buf)
        .map_err(ParakeetCliError::SourceIoError)?;
    let file_size = src
        .stream_position()
        .map_err(ParakeetCliError::SourceIoError)?;
    src.seek(SeekFrom::Start(0))
        .map_err(ParakeetCliError::SourceIoError)?;

    let tail_result = tencent::parse_tail(&tail_buf);

    let (key, tail_len) = match args.key {
        Some(user_key) => {
            let key = match args.key_type {
                QMCKeyType::Key => user_key.content,
                QMCKeyType::EKey => ekey::decrypt(user_key.content)
                    .map_err(ParakeetCliError::QMCKeyDecryptionError)?,
            };
            let tail_len = match args.tail_trim {
                Some(value) => value as usize,
                None => match tail_result {
                    Ok(m) => m.get_tail_len(),
                    _ => 0,
                },
            };
            (key, tail_len)
        }
        None => {
            let tail_result = tail_result.map_err(ParakeetCliError::QMCTailParseError)?;
            let tail_key = tail_result
                .get_key()
                .ok_or(ParakeetCliError::QMCKeyRequired)?;
            (Box::from(tail_key), tail_result.get_tail_len())
        }
    };

    log.info(format!(
        "key accepted (key_len={}, tail_len={})",
        key.len(),
        tail_len
    ));

    let cipher = QMCv2::from_key(key);
    let file_size = file_size as usize;
    let bytes_written = decrypt_file_stream(&log, cipher, &mut dst, &mut src, 0, Some(file_size))?;
    log.info(format!("decrypt: done, written {} bytes", bytes_written));

    Ok(())
}
