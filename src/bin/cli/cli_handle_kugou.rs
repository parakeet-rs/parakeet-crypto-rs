use std::{fs::File, process};

use argh::FromArgs;
use parakeet_crypto::{
    interfaces::decryptor::Decryptor,
    kugou::{self, kgm_crypto::KGMCryptoConfig, kgm_header::KGMHeader},
};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath, CliFriendlyDecryptionError},
};

/// Handle Kugou encryption/decryption.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "kugou")]
pub struct KugouOptions {
    /// slot key 1 content.
    #[argh(option)]
    slot_key_1: CliBinaryContent,

    /// enable encrypt mode, with specified template header.
    /// signature will be re-generated for given key in the template.
    #[argh(option)]
    encrypt_header: Option<CliBinaryContent>,

    /// file key expansion table for encryption schema v4.
    #[argh(option)]
    v4_file_key_expansion_table: Option<CliBinaryContent>,

    /// slot key expansion table for encryption schema v4.
    #[argh(option)]
    v4_slot_key_expansion_table: Option<CliBinaryContent>,

    /// input file path.
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file path.
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_kugou(args: KugouOptions) {
    let log = CliLogger::new("Kugou");

    let mut config = KGMCryptoConfig::default();

    if let Some(table) = args.v4_file_key_expansion_table {
        config.v4_file_key_expand_table = table.content;
        log.info("(v4) file key expansion table accepted.");
    }

    if let Some(table) = args.v4_slot_key_expansion_table {
        config.v4_slot_key_expand_table = table.content;
        log.info("(v4) slot key expansion table accepted.");
    }

    // Configure key slots
    config.slot_keys.insert(1, args.slot_key_1.content);

    let kgm = kugou::kgm_decryptor::KGM::new(&config);
    let mut input_file = File::open(args.input_file.path).unwrap();
    let mut output_file = File::create(args.output_file.path).unwrap();

    let operation = if args.encrypt_header.is_some() {
        "Encryption"
    } else {
        "Decryption"
    };

    if let Some(encrypt_header) = args.encrypt_header {
        let mut header = KGMHeader::from_bytes(&encrypt_header.content).unwrap_or_else(|err| {
            log.error(&format!("Could not parse header: {:?}", err));
            process::exit(1)
        });

        kgm.encrypt(&mut header, &mut input_file, &mut output_file)
    } else {
        kgm.decrypt(&mut input_file, &mut output_file)
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
