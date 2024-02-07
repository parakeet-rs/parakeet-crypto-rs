use crate::cli::commands::ParakeetCryptoName as Command;

mod commands;
mod logger;
mod utils;

mod cli_error;
mod cli_handle_kugou;
mod cli_handle_kuwo;
mod cli_handle_qmc1;
mod cli_handle_qmc2;
mod cli_handle_ximalaya_android;

pub fn parakeet_main() {
    let options: commands::ParakeetCLIArgRoot = argh::from_env();
    let log = logger::CliLogger::new("main");

    #[cfg(debug_assertions)]
    {
        log.warn("parakeet_cli was built without optimizations.");
        log.warn("Use release build for better performance.");
    }

    let cmd_result = match options.command {
        Command::ModuleTencentQMCv1(options) => cli_handle_qmc1::handle(options),
        Command::ModuleTencentQMCv2(options) => cli_handle_qmc2::handle(options),
        Command::ModuleKugou(options) => cli_handle_kugou::handle(options),
        Command::ModuleKuwo(options) => cli_handle_kuwo::handle(options),
        Command::ModuleXimalayaAndroid(options) => cli_handle_ximalaya_android::handle(options),
    };

    match cmd_result {
        Ok(_) => (),
        Err(err) => {
            log.error(format!("Command failed with error: {}", err).as_str());
        }
    }
}
