use std::{fs::File, process};

use argh::FromArgs;
use parakeet_crypto::ximalaya;

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath, CliFriendlyDecryptionError},
};

/// Handle x2m/x3m encryption/decryption.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "xmly")]
pub struct XimalayaOptions {
    /// scramble table (u16 x 1024 items, little-endian)
    #[argh(option)]
    scramble_table: CliBinaryContent,

    /// X2M/X3M key.
    /// 4-bytes = X2M
    /// 32-bytes = X3M
    #[argh(option)]
    key: CliBinaryContent,

    /// encrypt instead of decrypt.
    /// default to decrypt.
    #[argh(switch)]
    encrypt: bool,

    /// input file path.
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file path.
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_xmly(args: XimalayaOptions) {
    let log = CliLogger::new("XMLY");

    if args.scramble_table.content.len() != 2048 {
        log.error(&format!(
            "expecting scramble-table to have a size of 2048, got {} instead.",
            args.scramble_table.content.len()
        ));
        process::exit(1);
    }

    let mut scramble_table = [0usize; 1024];
    for (i, item) in scramble_table.iter_mut().enumerate() {
        let mut buffer = [0u8; 2];
        buffer.copy_from_slice(&args.scramble_table.content[i * 2..i * 2 + 2]);
        *item = u16::from_le_bytes(buffer) as usize;
    }

    let operation = if args.encrypt {
        "Encryption"
    } else {
        "Decryption"
    };

    let xmly =
        ximalaya::new_from_key(&args.key.content[..], &scramble_table).unwrap_or_else(|err| {
            log.error(&format!(
                "Create encryptor/decryptor using key failed: {}",
                err.to_friendly_error()
            ));
            process::exit(1)
        });
    let mut input_file = File::open(args.input_file.path).unwrap();
    let mut output_file = File::create(args.output_file.path).unwrap();

    if args.encrypt {
        xmly.encrypt(&mut input_file, &mut output_file)
    } else {
        xmly.decrypt(&mut input_file, &mut output_file)
    }
    .unwrap_or_else(|err| {
        log.error(&format!(
            "{} failed: {}",
            operation,
            err.to_friendly_error()
        ));
        process::exit(1)
    });

    log.info(&format!("{} OK.", operation));
}
