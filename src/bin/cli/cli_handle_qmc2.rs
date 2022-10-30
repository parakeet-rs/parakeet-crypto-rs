use std::{
    fs::{self, File},
    path::Path,
};

use parakeet_crypto::{
    interfaces::decryptor::Decryptor,
    tencent::{qmc2, qmc_footer_parser::QMCFooterParser},
};

fn read_key_from_parameter(value: &str) -> Option<Box<[u8]>> {
    if let Some(value) = value.strip_prefix('@') {
        let file_content = fs::read(Path::new(value)).unwrap();
        Some(file_content.into())
    } else if let Some(value) = value.strip_prefix("base64:") {
        let content = base64::decode(&value).unwrap();
        Some(content.into())
    } else {
        None
    }
}

pub fn cli_handle_qmc2(args: Vec<String>) {
    let mut parser = QMCFooterParser::new(0);
    let mut i = 2;
    loop {
        let arg: &str = &args[i];
        i += 1;

        if arg.starts_with("--") {
            match arg {
                "--seed" => {
                    parser.set_seed(args[i].parse::<u8>().unwrap());
                    i += 1;
                }

                "--key1" => {
                    let mut buffer = [0u8; 16];
                    let value = read_key_from_parameter(&args[i]).unwrap();
                    buffer.copy_from_slice(&value);
                    parser.set_key_stage1(buffer);

                    i += 1;
                }

                "--key2" => {
                    let mut buffer = [0u8; 16];
                    let value = read_key_from_parameter(&args[i]).unwrap();
                    buffer.copy_from_slice(&value);
                    parser.set_key_stage2(buffer);

                    i += 1;
                }

                "--" => {
                    break;
                }

                _ => {
                    panic!("Unknown argument: {:?}", arg);
                }
            }
        } else {
            i -= 1;
            break;
        }

        if i >= args.len() {
            break;
        }
    }

    match args[1].as_str() {
        "qmc2" => {
            if args.len() - i != 2 {
                panic!("incorrect number of arguments: {:?}", args.len());
            }

            let qmc2_map = qmc2::QMC2::new(parser);
            qmc2_map
                .decrypt(
                    &mut File::open(&args[i]).unwrap(),
                    &mut File::create(&args[i + 1]).unwrap(),
                )
                .unwrap();
        }

        _ => panic!("unknown command: {:?}", args[1]),
    }
}
