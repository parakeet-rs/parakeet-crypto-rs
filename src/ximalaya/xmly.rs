use crate::interfaces::decryptor::DecryptorError;

use super::xmly_crypto::XimalayaCrypto;

pub fn new_from_key(
    key: &[u8],
    scramble_table: &[usize; 1024],
) -> Result<XimalayaCrypto, DecryptorError> {
    let mut key_final = [0u8; 32];

    match key.len() {
        4 => {
            for i in (0..32).step_by(4) {
                key_final[i..i + 4].copy_from_slice(key);
            }
        }

        32 => {
            key_final.copy_from_slice(key);
        }

        _ => return Err(DecryptorError::XimalayaCountNotFindImplementation),
    };

    Ok(XimalayaCrypto::new(&key_final, scramble_table))
}

#[cfg(test)]
mod tests {
    use crate::interfaces::decryptor::Decryptor;

    use std::{
        fs::{self, File},
        path::PathBuf,
    };

    fn test_xmly_file(xmly_type: &str) {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path_encrypted = d.join(format!("sample/test_xmly.{}", xmly_type));
        let path_source = d.join("sample/test_121529_32kbps.ogg");
        let path_content_key = d.join(format!("sample/test_{}_key.bin", xmly_type));
        let path_scramble_table = d.join("sample/test_xmly_scramble_table.bin");

        let mut decrypted_content = Vec::new();

        let mut file_encrypted = File::open(path_encrypted).unwrap();
        let source_content = fs::read(path_source.as_path()).unwrap();
        let content_key = fs::read(path_content_key.as_path()).unwrap();
        let scramble_table_bin = fs::read(path_scramble_table.as_path()).unwrap();

        let mut scramble_table = [0usize; 1024];
        for (i, item) in scramble_table.iter_mut().enumerate() {
            let mut buffer = [0u8; 2];
            buffer.copy_from_slice(&scramble_table_bin[i * 2..i * 2 + 2]);
            *item = u16::from_le_bytes(buffer) as usize;
        }

        let decryptor = super::new_from_key(&content_key, &scramble_table).unwrap();
        decryptor
            .decrypt(&mut file_encrypted, &mut decrypted_content)
            .unwrap();

        assert_eq!(source_content, decrypted_content, "mismatched content");
    }

    #[test]
    fn test_x2m() {
        test_xmly_file("x2m");
    }

    #[test]
    fn test_x3m() {
        test_xmly_file("x3m");
    }
}
