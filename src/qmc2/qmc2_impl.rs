use super::{crypto_rc4::CryptoRC4, tails};
use crate::{
    interfaces::{Decryptor, DecryptorError, StreamDecryptor},
    utils::decrypt_full_stream,
    QmcV1,
};
use std::io::{Read, Seek, Write};

/// QMC2 decryptor for
pub struct QMC2 {
    parser: tails::QMCTailParser,
}

impl QMC2 {
    pub fn new(parser: tails::QMCTailParser) -> QMC2 {
        QMC2 { parser }
    }

    pub fn new_stream_decryptor(key: &[u8]) -> Box<dyn StreamDecryptor> {
        match key.len() {
            usize::MIN..=300 => {
                if let Some(qmc1) = QmcV1::new_map(key) {
                    Box::new(qmc1)
                } else {
                    // Treat it as 256 key.
                    let mut new_key = [0u8; 256];
                    new_key[..key.len()].copy_from_slice(key);
                    Box::new(QmcV1::new_map(&new_key).unwrap())
                }
            }

            _ => Box::new(CryptoRC4::new(key)),
        }
    }
}

impl Decryptor for QMC2 {
    fn check<R>(&self, from: &mut R) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
    {
        self.parser.parse_from_stream(from).and(Ok(()))
    }

    fn decrypt<R, W>(&mut self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        let (trim_right, key) = self.parser.parse_from_stream(from)?;
        let mut decryptor = Self::new_stream_decryptor(&key[..]);
        decrypt_full_stream(&mut *decryptor, from, to, Some(trim_right))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::PathBuf,
    };

    use super::*;

    const TEST_KEY_SEED: u8 = 123;
    const TEST_KEY_STAGE1: &[u8; 16] = &[
        11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28,
    ];
    const TEST_KEY_STAGE2: &[u8; 16] = &[
        31, 32, 33, 34, 35, 36, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48,
    ];

    fn test_qmc2_file(qmc2_type: &str) {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path_encrypted = d.join(format!("sample/test_qmc2_{}.mgg", qmc2_type));
        let path_source = d.join("sample/test_121529_32kbps.ogg");
        let mut decrypted_content = Vec::new();

        let mut qmc2 = super::QMC2::new(tails::QMCTailParser::new_enc_v2(
            TEST_KEY_SEED,
            *TEST_KEY_STAGE1,
            *TEST_KEY_STAGE2,
        ));

        let mut file_encrypted = File::open(path_encrypted).unwrap();
        let source_content = fs::read(path_source.as_path()).unwrap();
        qmc2.decrypt(&mut file_encrypted, &mut decrypted_content)
            .unwrap();

        assert_eq!(source_content, decrypted_content, "mismatched content");
    }

    #[test]
    fn test_qmc2_rc4_enc_v2() {
        test_qmc2_file("rc4_EncV2");
    }

    #[test]
    fn test_qmc2_rc4() {
        test_qmc2_file("rc4");
    }

    #[test]
    fn test_qmc2_map() {
        test_qmc2_file("map");
    }
}
