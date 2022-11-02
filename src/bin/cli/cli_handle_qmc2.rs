use std::{fs::File, process};

use argh::FromArgs;
use parakeet_crypto::{
    interfaces::decryptor::Decryptor,
    tencent::{qmc2, qmc2_footer_parser::QMCFooterParser},
};

use crate::cli::logger::CliLogger;

use super::utils::{CliBinaryArray, CliFilePath};

/// Handle QMC2 File.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "qmc2")]
pub struct QMC2Options {
    /// embed key decryption seed.
    #[argh(option)]
    seed: u8,

    /// (EncV2): Mix key 1 / Stage 1 key
    #[argh(option)]
    key1: Option<CliBinaryArray<16>>,

    /// (EncV2): Mix key 2 / Stage 2 key
    #[argh(option)]
    key2: Option<CliBinaryArray<16>>,

    /// input file name/path
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_qmc2(args: QMC2Options) {
    let log = CliLogger::new("QMC2");

    let mut parser = QMCFooterParser::new(args.seed);

    if let Some(key1) = args.key1 {
        parser.set_key_stage1(key1.content);
        log.info("(EncV2) Stage 1 key accepted.");
    }

    if let Some(key2) = args.key2 {
        parser.set_key_stage2(key2.content);
        log.info("(EncV2) Stage 2 key accepted.");
    }

    if args.input_file.path == args.output_file.path {
        log.error("Decrypt the file in-place will not work.");
        process::exit(1);
    }

    let qmc2_map = qmc2::QMC2::new(parser);
    qmc2_map
        .decrypt(
            &mut File::open(args.input_file.path).unwrap(),
            &mut File::create(args.output_file.path).unwrap(),
        )
        .unwrap_or_else(|err| {
            log.error(&format!("Decryption failed: {:?}", err));
            process::exit(1);
        });
    log.info("Decryption OK.");
}
