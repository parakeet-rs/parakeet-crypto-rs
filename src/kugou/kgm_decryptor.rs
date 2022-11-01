use std::io::SeekFrom;

use crate::interfaces::decryptor::{Decryptor, DecryptorError, SeekReadable};

use super::{
    kgm_crypto::KGMCryptoConfig,
    kgm_crypto_factory::{create_kgm_decryptor, create_kgm_encryptor},
    kgm_header::KGMHeader,
};

pub struct KGM {
    config: KGMCryptoConfig,
}

impl KGM {
    pub fn new(config: &KGMCryptoConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub fn encrypt(
        &self,
        header: &mut KGMHeader,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
    ) -> Result<(), DecryptorError> {
        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;
        let mut encryptor = create_kgm_encryptor(header, &self.config)?;

        let header = header.to_bytes();
        to.write_all(&header).or(Err(DecryptorError::IOError))?;

        let mut bytes_left = from
            .seek(SeekFrom::End(0))
            .or(Err(DecryptorError::IOError))? as u64;

        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;

        let mut offset = 0;
        let mut buffer = [0u8; 0x1000];
        while bytes_left > 0 {
            let bytes_read = from.read(&mut buffer).or(Err(DecryptorError::IOError))?;
            encryptor.encrypt(offset, &mut buffer[..bytes_read]);
            to.write_all(&buffer[..bytes_read])
                .or(Err(DecryptorError::IOError))?;
            offset += bytes_read as u64;
            bytes_left -= bytes_read as u64;
        }

        Ok(())
    }
}

impl Decryptor for KGM {
    fn check(&self, from: &mut dyn SeekReadable) -> Result<bool, DecryptorError> {
        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;

        let header = KGMHeader::from_reader(from).or(Err(DecryptorError::IOError))?;

        create_kgm_decryptor(&header, &self.config).and(Ok(true))
    }

    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn std::io::Write,
    ) -> Result<(), DecryptorError> {
        from.seek(SeekFrom::Start(0))
            .or(Err(DecryptorError::IOError))?;

        let header = KGMHeader::from_reader(from).or(Err(DecryptorError::IOError))?;
        let mut decryptor = create_kgm_decryptor(&header, &self.config)?;

        let mut bytes_left = from
            .seek(SeekFrom::End(0))
            .or(Err(DecryptorError::IOError))?
            - header.offset_to_data as u64;

        from.seek(SeekFrom::Start(header.offset_to_data as u64))
            .or(Err(DecryptorError::IOError))?;

        let mut offset = 0;
        let mut buffer = [0u8; 0x1000];
        while bytes_left > 0 {
            let bytes_read = from.read(&mut buffer).or(Err(DecryptorError::IOError))?;
            decryptor.decrypt(offset, &mut buffer[..bytes_read]);
            to.write_all(&buffer[..bytes_read])
                .or(Err(DecryptorError::IOError))?;
            offset += bytes_read as u64;
            bytes_left -= bytes_read as u64;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::PathBuf,
    };

    use super::*;

    const TEST_SLOT_KEY1: [u8; 4] = *b"09AZ";

    fn test_kgm_file(kgm_type: &str) {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path_encrypted = d.join(format!("sample/test_kgm_{}.kgm", kgm_type));
        let path_source = d.join("sample/test_121529_32kbps.ogg");
        let path_v4_filekey_table = d.join("sample/test_kgm_v4_filekey_table.bin");
        let path_v4_slotkey_table = d.join("sample/test_kgm_v4_slotkey_table.bin");

        let mut decrypted_content = Vec::new();

        let mut file_encrypted = File::open(path_encrypted).unwrap();
        let source_content = fs::read(path_source.as_path()).unwrap();
        let v4_filekey_table = fs::read(path_v4_filekey_table.as_path()).unwrap();
        let v4_slotkey_table = fs::read(path_v4_slotkey_table.as_path()).unwrap();

        let mut config = KGMCryptoConfig::default();
        config.slot_keys.insert(1, TEST_SLOT_KEY1.into());
        config.v4_file_key_expand_table = v4_filekey_table.into();
        config.v4_slot_key_expand_table = v4_slotkey_table.into();

        let kgm = super::KGM::new(&config);
        kgm.decrypt(&mut file_encrypted, &mut decrypted_content)
            .unwrap();

        assert_eq!(source_content, decrypted_content, "mismatched content");
    }

    #[test]
    fn test_kgm_enc_v2() {
        test_kgm_file("v2");
    }

    #[test]
    fn test_kgm_enc_v3() {
        test_kgm_file("v3");
    }

    #[test]
    fn test_kgm_enc_v4() {
        test_kgm_file("v4");
    }
}
