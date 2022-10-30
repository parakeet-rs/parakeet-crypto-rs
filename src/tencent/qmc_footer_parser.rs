use crate::interfaces::decryptor::{DecryptorError, SeekReadable};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::io::SeekFrom;
use std::str;

use super::key_utils::make_simple_key;

const MAGIC_ANDROID_S_TAG: u32 = u32::from_le_bytes(*b"STag");
const MAGIC_ANDROID_Q_TAG: u32 = u32::from_le_bytes(*b"QTag");
const ENC_V2_PREFIX_TAG: &[u8] = b"QQMusic EncV2,Key:";

/// QMC2's file footer parser.
/// This parser is used to extract the file key for decryption, as well as the
///   number of bytes to ignore in the end of the file.
pub struct QMCFooterParser {
    seed: u8,
    enc_v2_key_stage1: [u8; 16],
    enc_v2_key_stage2: [u8; 16],
}

impl QMCFooterParser {
    pub fn new(seed: u8) -> QMCFooterParser {
        QMCFooterParser {
            seed,
            enc_v2_key_stage1: [0u8; 16],
            enc_v2_key_stage2: [0u8; 16],
        }
    }

    pub fn new_enc_v2(
        seed: u8,
        enc_v2_key_stage1: [u8; 16],
        enc_v2_key_stage2: [u8; 16],
    ) -> QMCFooterParser {
        QMCFooterParser {
            seed,
            enc_v2_key_stage1,
            enc_v2_key_stage2,
        }
    }

    pub fn set_seed(&mut self, seed: u8) {
        self.seed = seed;
    }

    pub fn set_key_stage1(&mut self, key: [u8; 16]) {
        self.enc_v2_key_stage1 = key;
    }

    pub fn set_key_stage2(&mut self, key: [u8; 16]) {
        self.enc_v2_key_stage2 = key;
    }

    pub fn parse(
        &self,
        input: &mut dyn SeekReadable,
    ) -> Result<(usize, Box<[u8]>), DecryptorError> {
        input
            .seek(SeekFrom::End(-4))
            .or(Err(DecryptorError::IOError))?;

        let magic = input
            .read_u32::<LittleEndian>()
            .or(Err(DecryptorError::IOError))?;

        let (trim_right, embed_key) = match magic {
            MAGIC_ANDROID_S_TAG => return Err(DecryptorError::QMCAndroidSTag),
            MAGIC_ANDROID_Q_TAG => {
                input
                    .seek(SeekFrom::End(-8))
                    .or(Err(DecryptorError::IOError))?;

                let meta_size = input
                    .read_u32::<BigEndian>()
                    .or(Err(DecryptorError::IOError))?;

                let trim_right = meta_size as usize + 8;

                let mut buffer = vec![0u8; meta_size as usize];
                input
                    .seek(SeekFrom::End(-8 - (meta_size as i64)))
                    .or(Err(DecryptorError::IOError))?;
                input
                    .read_exact(&mut buffer)
                    .or(Err(DecryptorError::IOError))?;

                let embed_key_size = buffer
                    .iter()
                    .position(|v| *v == b',')
                    .ok_or(DecryptorError::QMCAndroidQTagInvalid)?;

                buffer.truncate(embed_key_size);

                (trim_right, buffer)
            }
            0..=0x400 => {
                input
                    .seek(SeekFrom::End(-4 - (magic as i64)))
                    .or(Err(DecryptorError::IOError))?;

                let trim_right = magic as usize + 4;

                let mut buffer = vec![0u8; magic as usize];
                input
                    .read_exact(&mut buffer)
                    .or(Err(DecryptorError::IOError))?;

                (trim_right, buffer)
            }
            _ => return Err(DecryptorError::QMCInvalidFooter(magic)),
        };

        let embed_key = str::from_utf8(&embed_key).or(Err(DecryptorError::StringEncodeError))?;
        let embed_key = embed_key.trim_end_matches(char::from(0));
        let embed_key = base64::decode(embed_key).map_err(DecryptorError::Base64DecodeError)?;

        if embed_key.starts_with(ENC_V2_PREFIX_TAG) {
            self.decrypt_key_v2(&embed_key[ENC_V2_PREFIX_TAG.len()..])
        } else {
            self.decrypt_key_v1(&embed_key)
        }
        .map(|r| (trim_right, r))
    }

    fn decrypt_key_v1(&self, embed_key: &[u8]) -> Result<Box<[u8]>, DecryptorError> {
        let (header, body) = embed_key.split_at(8);
        let simple_key = make_simple_key(self.seed, 8);

        let mut tea_key = [0u8; 16];
        for i in (0..16).step_by(2) {
            tea_key[i] = simple_key[i / 2];
            tea_key[i + 1] = header[i / 2];
        }

        let final_key = tc_tea::decrypt(body, &tea_key).ok_or(DecryptorError::TEADecryptError)?;

        Ok([header, &final_key].concat().into())
    }

    fn decrypt_key_v2(&self, embed_key: &[u8]) -> Result<Box<[u8]>, DecryptorError> {
        let key = tc_tea::decrypt(embed_key, self.enc_v2_key_stage1)
            .and_then(|key| tc_tea::decrypt(key, self.enc_v2_key_stage2))
            .ok_or(DecryptorError::TEADecryptError)?;
        let key = str::from_utf8(&key).or(Err(DecryptorError::StringEncodeError))?;
        let key = base64::decode(key).map_err(DecryptorError::Base64DecodeError)?;

        self.decrypt_key_v1(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::decryptor::DecryptorError;
    use std::io::Cursor;

    const TEST_KEY_SEED: u8 = 123;
    const TEST_KEY_STAGE1: &[u8; 16] = &[
        11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28,
    ];
    const TEST_KEY_STAGE2: &[u8; 16] = &[
        31, 32, 33, 34, 35, 36, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48,
    ];

    fn create_default_key_v1() -> Box<[u8]> {
        let (header, body) = b"12345678Some Key".split_at(8);

        let simple_key = make_simple_key(TEST_KEY_SEED, 8);
        let mut tea_key = [0u8; 16];
        for i in (0..16).step_by(2) {
            tea_key[i] = simple_key[i / 2];
            tea_key[i + 1] = header[i / 2];
        }

        let second_half_encrypted = tc_tea::encrypt(&body, tea_key).unwrap();
        let embed_key = [header, &second_half_encrypted].concat();

        base64::encode(embed_key).as_bytes().into()
    }

    fn create_default_key_v2() -> Box<[u8]> {
        let embed_key_v1 = create_default_key_v1();

        let embed_key_v2 = tc_tea::encrypt(embed_key_v1, TEST_KEY_STAGE2)
            .and_then(|key| tc_tea::encrypt(key, TEST_KEY_STAGE1))
            .unwrap();

        let embed_key_v2 = [ENC_V2_PREFIX_TAG, &embed_key_v2].concat();

        base64::encode(embed_key_v2).as_bytes().into()
    }

    #[test]
    fn parse_v1_pc() {
        let parser = QMCFooterParser::new(TEST_KEY_SEED);
        let mut footer = create_default_key_v1().to_vec();
        let mut footer_len = (footer.len() as u32).to_le_bytes().to_vec();
        footer.append(&mut footer_len);

        let expected_trim_right = footer.len();
        let mut stream = Cursor::new(footer);

        let (trim_right, decrypted) = parser.parse(&mut stream).unwrap();
        assert_eq!(trim_right, expected_trim_right);
        assert_eq!(decrypted.to_vec(), b"12345678Some Key".to_vec());
    }

    #[test]
    fn parse_v2_pc() {
        let parser = QMCFooterParser::new_enc_v2(TEST_KEY_SEED, *TEST_KEY_STAGE1, *TEST_KEY_STAGE2);
        let mut footer = create_default_key_v2().to_vec();
        let mut footer_len = (footer.len() as u32).to_le_bytes().to_vec();
        footer.append(&mut footer_len);

        let expected_trim_right = footer.len();
        let mut stream = Cursor::new(footer);

        let (trim_right, decrypted) = parser.parse(&mut stream).unwrap();
        assert_eq!(trim_right, expected_trim_right);
        assert_eq!(decrypted.to_vec(), b"12345678Some Key".to_vec());
    }

    #[test]
    fn parse_v2_q_tag() {
        let parser = QMCFooterParser::new_enc_v2(TEST_KEY_SEED, *TEST_KEY_STAGE1, *TEST_KEY_STAGE2);
        let mut footer = create_default_key_v2().to_vec();
        let mut tmp = Vec::from(b",12345,2" as &[u8]);
        footer.append(&mut tmp);
        let mut footer_len = (footer.len() as u32).to_be_bytes().to_vec();
        footer.append(&mut footer_len);
        let mut tmp = Vec::from(b"QTag" as &[u8]);
        footer.append(&mut tmp);

        let expected_trim_right = footer.len();
        let mut stream = Cursor::new(footer);

        let (trim_right, decrypted) = parser.parse(&mut stream).unwrap();
        assert_eq!(trim_right, expected_trim_right);
        assert_eq!(decrypted.to_vec(), b"12345678Some Key".to_vec());
    }

    #[test]
    fn parse_non_sense() {
        let parser = QMCFooterParser::new(0);
        let footer = vec![0xff, 0xff, 0xff, 0xff];
        let mut stream = Cursor::new(footer);
        assert!(
            parser.parse(&mut stream).is_err(),
            "should not allow 0xffffffff magic"
        )
    }

    #[test]
    fn parse_android_s_tag() {
        let parser = QMCFooterParser::new(0);
        let footer = b"1111STag".to_vec();
        let mut stream = Cursor::new(footer);
        assert_eq!(
            parser.parse(&mut stream).unwrap_err(),
            DecryptorError::QMCAndroidSTag
        );
    }
}
