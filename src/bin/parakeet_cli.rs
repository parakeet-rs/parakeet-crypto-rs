use cli::{cli_handle_qmc1, cli_handle_qmc2, commands::ParakeetCLIArgRoot};

use cli::commands::ParakeetCryptoName as Command;

mod cli;

fn main() {
    let options: ParakeetCLIArgRoot = argh::from_env();

    match options.command {
        Command::ModuleQMC1(options) => cli_handle_qmc1(options),
        Command::ModuleQMC2(options) => cli_handle_qmc2(options),
    }
}
