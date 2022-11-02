use cli::{cli_handle_kugou, cli_handle_xmly};
use cli::{cli_handle_qmc1, cli_handle_qmc2, commands::ParakeetCLIArgRoot};

use cli::commands::ParakeetCryptoName as Command;

mod cli;

fn main() {
    let options: ParakeetCLIArgRoot = argh::from_env();

    #[cfg(debug_assertions)]
    {
        let log = cli::logger::CliLogger::new("main");
        log.warn("parakeet_cli was built without optimizations.");
        log.warn("Use release build for better performance.");
    }

    match options.command {
        Command::ModuleQMC1(options) => cli_handle_qmc1(options),
        Command::ModuleQMC2(options) => cli_handle_qmc2(options),
        Command::ModuleKGM(options) => cli_handle_kugou(options),
        Command::ModuleXMLY(options) => cli_handle_xmly(options),
    }
}
