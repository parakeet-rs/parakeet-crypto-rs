use std::io::Write;

use crate::interfaces::decryptor::{DecryptorError, SeekReadable};

use super::{
    key_utils::init_qmc_static_map_table,
    qmc_legacy_block::{qmc_legacy_decrypt_stream, QMCLegacyBlockDecryptor},
};

/// QMC2-Map decryption.
struct QMC2Map<'a> {
    key: &'a [u8],
    table: [u8; 0x8000],
}

impl QMC2Map<'_> {
    fn new(key: &[u8]) -> QMC2Map {
        let mut table = [0u8; 0x8000];
        init_qmc_static_map_table(&mut table, key, |i, key| {
            ((i * i + 71214) % (key.len() as u32)) as u8
        });

        QMC2Map { key, table }
    }

    /// Get the mask (used for XOR) for a given offset.
    /// The offset needs to be smaller than the table size.
    #[inline]
    fn get_mask_for_offset(&self, offset: usize) -> u8 {
        unsafe {
            // This struct's methods are private and not exposed.
            // Caller are ensuring that the offset is within the size of the table.
            if offset >= self.table.len() {
                std::hint::unreachable_unchecked()
            }
        }

        let key_index = self.table[offset];
        let xor_key = unsafe { *self.key.get_unchecked(key_index as usize) };
        let rotation = key_index.wrapping_add(4) & 0b0111;
        (xor_key << rotation) | (xor_key >> rotation)
    }
}

impl QMCLegacyBlockDecryptor for QMC2Map<'_> {
    /// Decrypt a block.
    /// `offset` is the offset of the block (0~0x7fff)
    #[inline]
    fn decrypt_block(&self, block: &mut [u8], offset: usize) {
        for (i, value) in block.iter_mut().enumerate() {
            *value ^= self.get_mask_for_offset(i + offset);
        }
    }
}

pub fn decrypt_map(
    embed_key: &[u8],
    trim_right: usize,
    from: &mut dyn SeekReadable,
    to: &mut dyn Write,
) -> Result<(), DecryptorError> {
    let decryptor = QMC2Map::new(embed_key);

    qmc_legacy_decrypt_stream(trim_right, &decryptor, from, to)
}
