use std::fs::File;

use parakeet_crypto::{interfaces::decryptor::Decryptor, tencent::qmc1};

use super::utils::read_key_from_parameter;

pub fn cli_handle_qmc1(args: Vec<String>) {
    let mut static_key = Box::from(&[] as &[u8]);

    let mut i = 2;
    loop {
        let arg: &str = &args[i];
        i += 1;

        if arg.starts_with("--") {
            match arg {
                "--static-key" => {
                    static_key = read_key_from_parameter(&args[i]).unwrap();
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
        "qmc1" => {
            if args.len() - i != 2 {
                panic!("incorrect number of arguments: {:?}", args.len());
            }

            let qmc1_map = qmc1::QMC1::new(&static_key[..]);
            qmc1_map
                .decrypt(
                    &mut File::open(&args[i]).unwrap(),
                    &mut File::create(&args[i + 1]).unwrap(),
                )
                .unwrap();
        }

        _ => panic!("unknown command: {:?}", args[1]),
    }
}
