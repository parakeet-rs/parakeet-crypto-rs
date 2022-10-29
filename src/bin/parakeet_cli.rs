use std::env;

mod cli;

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args[1].as_str();

    match command {
        "qmc2" => cli::cli_handle_qmc2(args),
        _ => panic!("Unknown command {:?}", command),
    }
}
