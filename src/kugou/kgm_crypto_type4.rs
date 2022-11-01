use crate::utils::md5;

use super::{
    kgm_crypto::{KGMCrypto, KGMCryptoConfig},
    utils::offset_to_xor_key,
};

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoType4 {
    expanded_slot_key_table: Box<[u8]>,
    expanded_file_key_table: Box<[u8]>,

    file_key_expanded: Box<[u8]>,
    slot_key_expanded: Box<[u8]>,
}

const DIGEST_INDEXES: [usize; 31] = [
    0x05, 0x0e, 0x0d, 0x02, 0x0c, 0x0a, 0x0f, 0x0b, //
    0x03, 0x08, 0x05, 0x06, 0x09, 0x04, 0x03, 0x07, //
    0x00, 0x0e, 0x0d, 0x06, 0x02, 0x0c, 0x0a, 0x0f, //
    0x01, 0x0b, 0x08, 0x07, 0x09, 0x04, 0x01,
];

impl KGMCryptoType4 {
    fn key_expansion(table: &[u8], key: &[u8]) -> Box<[u8]> {
        let md5_key = md5(key);

        let mut md5_final = [0u8; DIGEST_INDEXES.len()];
        for (i, v) in md5_final.iter_mut().enumerate() {
            *v = md5_key[DIGEST_INDEXES[i]];
        }
        let md5_final = md5_final;

        let final_key_size = 4 * (md5_final.len() - 1) * (key.len() - 1);
        let mut expanded_key = Vec::<u8>::with_capacity(final_key_size);
        for (i, &j) in md5_final.iter().enumerate().skip(1) {
            let temp = (i as u32).wrapping_mul(j as u32);

            for (k, &l) in table.iter().enumerate().skip(1) {
                let temp = temp.wrapping_mul(k as u32).wrapping_mul(l as u32);
                let bytes = temp.to_le_bytes();

                // (LittleEndian)   0x12345678
                // Memory:  [78] [56] [34] [12]
                //
                //    SHR:   00   08   10   18
                //       = 0x78 0x56 0x34 0x12
                //  Index:    0    1    2    3

                expanded_key.push(bytes[0]); // temp >> 0x00
                expanded_key.push(bytes[3]); // temp >> 0x18
                expanded_key.push(bytes[2]); // temp >> 0x10
                expanded_key.push(bytes[1]); // temp >> 0x08
            }
        }

        expanded_key.into()
    }
}

impl KGMCrypto for KGMCryptoType4 {
    fn configure(&mut self, config: &KGMCryptoConfig) {
        self.expanded_file_key_table = Box::from(&config.v4_file_key_expand_table[..]);
        self.expanded_slot_key_table = Box::from(&config.v4_slot_key_expand_table[..]);
    }

    fn expand_slot_key(&mut self, key: &[u8]) {
        let key = md5(key);
        let key = hex::encode(key);
        let key = base64::encode(key);
        let key = key.as_bytes();

        self.slot_key_expanded = Self::key_expansion(&self.expanded_slot_key_table, key);
    }

    fn expand_file_key(&mut self, key: &[u8]) {
        self.file_key_expanded = Self::key_expansion(&self.expanded_file_key_table, key);
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;

        let key1 = &self.slot_key_expanded;
        let key2 = &self.file_key_expanded;

        let key1_len = key1.len();
        let key2_len = key2.len();

        for item in buffer.iter_mut() {
            // XOR all bytes of a "u32" integer.
            let offset_key = offset_to_xor_key(offset);

            // Rust should be able to combine the mod/div in a single call..?
            let offset_usize = offset as usize;
            let key1_index = offset_usize % key1_len;
            let key2_index = (offset_usize / key1_len) % key2_len;

            let mut temp = *item;
            temp ^= key2[key2_index];
            temp ^= temp << 4;
            temp ^= key1[key1_index];
            temp ^= offset_key;
            *item = temp;

            offset += 1;
        }
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;

        let key1 = &self.slot_key_expanded;
        let key2 = &self.file_key_expanded;

        let key1_len = key1.len();
        let key2_len = key2.len();

        for item in buffer.iter_mut() {
            // XOR all bytes of a "u32" integer.
            let offset_key = offset_to_xor_key(offset);

            // Rust should be able to combine the mod/div in a single call..?
            let offset_usize = offset as usize;
            let key1_index = offset_usize % key1_len;
            let key2_index = (offset_usize / key1_len) % key2_len;

            let mut temp = *item;
            temp ^= offset_key;
            temp ^= key1[key1_index];
            temp ^= temp << 4;
            temp ^= key2[key2_index];
            *item = temp;

            offset += 1;
        }
    }
}
