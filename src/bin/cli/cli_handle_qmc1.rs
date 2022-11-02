use std::{fs::File, process};

use argh::FromArgs;
use parakeet_crypto::{interfaces::decryptor::Decryptor, tencent::qmc1};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath, CliFriendlyDecryptionError},
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
    let qmc1_map = qmc1::QMC1::new(&args.static_key.content);
    log.info(&format!(
        "Static key accepted (key{})",
        args.static_key.content.len()
    ));

    qmc1_map
        .decrypt(
            &mut File::open(args.input_file.path).unwrap(),
            &mut File::create(args.output_file.path).unwrap(),
        )
        .unwrap_or_else(|err| {
            log.error(&format!("Decryption failed: {}", err.to_friendly_error()));
            process::exit(1);
        });
    log.info("Decryption OK.");
}
