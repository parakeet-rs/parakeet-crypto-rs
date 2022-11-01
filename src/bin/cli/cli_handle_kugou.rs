use std::fs::File;

use parakeet_crypto::{
    interfaces::decryptor::Decryptor,
    kugou::{self, kgm_crypto::KGMCryptoConfig, kgm_header::KGMHeader},
};

use super::utils::read_key_from_parameter;

pub fn cli_handle_kugou(args: Vec<String>) {
    let mut encrypt_header = Box::<[u8]>::from([]);
    let mut config = KGMCryptoConfig::default();

    let mut i = 2;
    loop {
        let arg: &str = &args[i];
        i += 1;

        if let Some(key) = arg.strip_prefix("--slot-key-") {
            let slot_id = key.parse::<u32>().unwrap();
            let slot_key = read_key_from_parameter(&args[i]).unwrap();
            config.slot_keys.insert(slot_id, slot_key);
            i += 1;
        } else if arg.starts_with("--") {
            match arg {
                "--" => {
                    break;
                }

                "--encrypt-header" => {
                    encrypt_header = read_key_from_parameter(&args[i]).unwrap();
                    i += 1;
                }

                "--v4-file-key-expansion-table" => {
                    config.v4_file_key_expand_table = read_key_from_parameter(&args[i]).unwrap();
                    i += 1;
                }

                "--v4-slot-key-expansion-table" => {
                    config.v4_slot_key_expand_table = read_key_from_parameter(&args[i]).unwrap();
                    i += 1;
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
        "kugou" => {
            if args.len() - i != 2 {
                panic!("incorrect number of arguments: {:?}", args.len());
            }

            let kgm = kugou::kgm_decryptor::KGM::new(&config);
            let mut input_file = File::open(&args[i]).unwrap();
            let mut output_file = File::create(&args[i + 1]).unwrap();

            if encrypt_header.len() > 0 {
                let mut header = KGMHeader::from_bytes(&encrypt_header).unwrap();
                kgm.encrypt(&mut header, &mut input_file, &mut output_file)
                    .unwrap();
            } else {
                kgm.decrypt(&mut input_file, &mut output_file).unwrap();
            }
        }

        _ => panic!("unknown command: {:?}", args[1]),
    }
}
