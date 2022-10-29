use std::io::{SeekFrom, Write};

use crate::interfaces::decryptor::{DecryptorError, SeekReadable};

/// QMC2-Map decryption.
/// TODO: Move this to another file as it can be made generic for older QMC1 variant.
struct QMC2Map<'a> {
    key: &'a [u8],
    table: [u8; 0x8000],
}

impl QMC2Map<'_> {
    fn new(key: &[u8]) -> QMC2Map {
        // Derive cache table from key.
        let key_size = key.len();
        let mut table = [0u8; 0x8000];

        // (i * i + n) % m === ((i % m) * (i % m) + n) % m
        // table size from 0x7fff => key_size
        let mut small_table = vec![0u8; key_size].into_boxed_slice();
        let key_size = key_size as u32;
        for (i, item) in small_table.iter_mut().enumerate() {
            let i = i as u32;
            *item = ((i * i + 71214) % key_size) as u8;
        }

        // Populate the table
        let small_table_len = small_table.len();
        table[..small_table_len].copy_from_slice(&small_table);
        for (prev_index, i) in (small_table_len..table.len()).enumerate() {
            table[i] = table[prev_index];
        }

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

        let key = self.table[offset];
        let key_index = key as usize;

        unsafe {
            // values of key_index are always within the range during generation.
            if key_index >= self.key.len() {
                std::hint::unreachable_unchecked()
            }
        }

        let xor_key = self.key[key_index];
        let rotation = ((key & 0b0111) + 4) % 8;
        (xor_key << rotation) | (xor_key >> rotation)
    }

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
    let map = QMC2Map::new(embed_key);

    // Detect file size.
    let mut bytes_left = from
        .seek(SeekFrom::End(-(trim_right as i64)))
        .or(Err(DecryptorError::IOError))? as usize;

    // Move back to the beginning of the stream.
    from.seek(SeekFrom::Start(0))
        .or(Err(DecryptorError::IOError))?;

    // Decrypt a single block.
    macro_rules! decrypt_block {
        ($block:expr, $offset:expr) => {
            if bytes_left > 0 {
                let bytes_read = from
                    .read(&mut $block)
                    .or(Err(DecryptorError::IOError))?
                    .min(bytes_left);

                map.decrypt_block(&mut $block[0..bytes_read], $offset);
                to.write_all(&$block[0..bytes_read])
                    .or(Err(DecryptorError::IOError))?;
                bytes_left -= bytes_read;
            }
        };
    }

    let mut buffer = [0u8; 0x7fff];

    // Decrypt the first block:
    decrypt_block!(buffer, 0);

    // Decrypt the second block, which had an off-by-one error:
    decrypt_block!(&mut buffer[..1], 0x7fff);
    decrypt_block!(&mut buffer[1..], 1);

    // Decrypt the remaining blocks...
    while bytes_left > 0 {
        decrypt_block!(buffer, 0);
    }

    Ok(())
}
