pub(self) mod utils;

pub(crate) mod commands;
pub(crate) mod logger;

mod cli_handle_kugou;
mod cli_handle_qmc1;
mod cli_handle_qmc2;
mod cli_handle_xmly;

pub use cli_handle_kugou::cli_handle_kugou;
pub use cli_handle_qmc1::cli_handle_qmc1;
pub use cli_handle_qmc2::cli_handle_qmc2;
pub use cli_handle_xmly::cli_handle_xmly;
