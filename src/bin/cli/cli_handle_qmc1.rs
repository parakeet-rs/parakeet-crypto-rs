use std::{fs::File, process};

use argh::FromArgs;
use parakeet_crypto::{interfaces::Decryptor, QmcV1};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath},
};

/// Handle QMC1 File.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "qmc1")]
pub struct QMC1Options {
    /// static key for QMC1 decryption.
    #[argh(option)]
    static_key: CliBinaryContent,

    /// input file name/path
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_qmc1(args: QMC1Options) {
    let log = CliLogger::new("QMC1");
    let mut qmc1_static = match QmcV1::new_static(&args.static_key.content) {
        None => {
            log.error("key rejected, invalid length?");
            return;
        }
        Some(x) => x,
    };

    log.info(&format!(
        "Static key accepted (key{})",
        args.static_key.content.len()
    ));

    qmc1_static
        .decrypt(
            &mut File::open(args.input_file.path).unwrap(),
            &mut File::create(args.output_file.path).unwrap(),
        )
        .unwrap_or_else(|err| {
            log.error(&format!("Decryption failed: {err}"));
            process::exit(1);
        });
    log.info("Decryption OK.");
}
