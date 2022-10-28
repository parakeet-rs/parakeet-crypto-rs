use crate::interfaces::decryptor::{DecryptorError, SeekReadable};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::SeekFrom;

const MAGIC_ANDROID_S_TAG: u32 = u32::from_be_bytes(*b"STag");
const MAGIC_ANDROID_Q_TAG: u32 = u32::from_be_bytes(*b"QTag");

pub struct QMCFooterParser {
    seed: u8,
    enc_v2_key_stage1: [u8; 16],
    enc_v2_key_stage2: [u8; 16],
}

impl QMCFooterParser {
    pub fn new(
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

    pub fn parse(&self, input: &mut dyn SeekReadable) -> Result<Vec<u8>, DecryptorError> {
        input
            .seek(SeekFrom::End(-4))
            .map_err(DecryptorError::IOError)?;

        let magic = input
            .read_u32::<LittleEndian>()
            .map_err(DecryptorError::IOError)?;

        let _ekey = match magic {
            MAGIC_ANDROID_S_TAG => return Err(DecryptorError::QMCAndroidSTag),
            MAGIC_ANDROID_Q_TAG => return Err(DecryptorError::NotImplementedError("a".into())),
            0..=0x400 => return Err(DecryptorError::NotImplementedError("a".into())),
            _ => return Err(DecryptorError::QMCInvalidFooter(magic)),
        };

        // Ok(vec![0])
    }
}
