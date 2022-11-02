use argh::FromArgs;

use super::{cli_handle_qmc1::QMC1Options, cli_handle_qmc2::QMC2Options};

/// Test CLI tool for parakeet_crypto.
#[derive(FromArgs, Eq, PartialEq, Debug)]
pub struct ParakeetCLIArgRoot {
    #[argh(subcommand)]
    pub command: ParakeetCryptoName,
}

#[derive(FromArgs, Eq, PartialEq, Debug)]
#[argh(subcommand)]
pub enum ParakeetCryptoName {
    ModuleQMC1(QMC1Options),
    ModuleQMC2(QMC2Options),
}
