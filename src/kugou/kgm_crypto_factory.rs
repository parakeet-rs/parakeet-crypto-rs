use crate::interfaces::decryptor::DecryptorError;

use super::{
    kgm_crypto::{KGMCrypto, KGMCryptoConfig},
    kgm_crypto_type2::KGMCryptoType2,
    kgm_crypto_type3::KGMCryptoType3,
    kgm_crypto_type4::KGMCryptoType4,
    kgm_header::KGMHeader,
};

const EXPECTED_DECRYPTION_RESULT: [u8; 16] = [
    0x38, 0x85, 0xED, 0x92, 0x79, 0x5F, 0xF8, 0x4C, //
    0xB3, 0x03, 0x61, 0x41, 0x16, 0xA0, 0x1D, 0x47, //
];

#[inline]
fn create_kgm_crypto(
    header: &KGMHeader,
    config: &KGMCryptoConfig,
) -> Result<Box<dyn KGMCrypto>, DecryptorError> {
    if let Some(slot_key) = config.slot_keys.get(&header.key_slot) {
        let mut decryptor: Box<dyn KGMCrypto> = match header.crypto_version {
            2 => Box::from(KGMCryptoType2::default()),
            3 => Box::from(KGMCryptoType3::default()),
            4 => Box::from(KGMCryptoType4::default()),
            _ => {
                return Err(DecryptorError::KGMUnsupportedEncryptionType(
                    header.crypto_version,
                ))
            }
        };

        // Configure the decryptor...
        decryptor.configure(config);

        // Key expansion
        decryptor.expand_slot_key(slot_key);
        decryptor.expand_file_key(&header.file_key);

        Ok(decryptor)
    } else {
        Err(DecryptorError::KGMInvalidKeySlotError(header.key_slot))
    }
}

pub fn create_kgm_decryptor(
    header: &KGMHeader,
    config: &KGMCryptoConfig,
) -> Result<Box<dyn KGMCrypto>, DecryptorError> {
    let mut decryptor = create_kgm_crypto(header, config)?;

    // Decryption test
    let mut test_data = header.decryptor_test_data;
    decryptor.decrypt(0, &mut test_data);
    if EXPECTED_DECRYPTION_RESULT == test_data {
        Ok(decryptor)
    } else {
        Err(DecryptorError::KGMInvalidFileKey)
    }
}

pub fn create_kgm_encryptor(
    header: &mut KGMHeader,
    config: &KGMCryptoConfig,
) -> Result<Box<dyn KGMCrypto>, DecryptorError> {
    let mut encryptor = create_kgm_crypto(header, config)?;

    // Key verification signature generation
    header.decryptor_test_data = EXPECTED_DECRYPTION_RESULT;
    encryptor.encrypt(0, &mut header.decryptor_test_data);

    Ok(encryptor)
}
