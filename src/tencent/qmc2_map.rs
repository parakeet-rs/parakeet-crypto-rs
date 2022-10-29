use std::io::{SeekFrom, Write};

use crate::interfaces::decryptor::{DecryptorError, SeekReadable};

struct QMC2Map<'a> {
    key: &'a [u8],
    table: [u8; 0x7FFF],
}

impl QMC2Map<'_> {
    fn new(key: &[u8]) -> QMC2Map {
        // Derive cache table from key.
        let key_len = key.len() as u64;
        let mut table = [0u8; 0x7FFF];

        for (i, v) in table.iter_mut().enumerate() {
            let offset = i as u64;
            *v = offset
                .wrapping_mul(offset)
                .wrapping_add(71214)
                .wrapping_rem(key_len) as u8;
        }

        QMC2Map { key, table }
    }

    // First block with size of 0x7FFF, then 0x7FFE.
    #[inline]
    fn decrypt_block(&self, block: &mut [u8]) {
        debug_assert!(
            block.len() <= self.table.len(),
            "block size should not exceed table size"
        );

        for (i, value) in block.iter_mut().enumerate() {
            let key = self.table[i];
            let xor_key = self.key[key as usize];
            let rotation = ((key & 0b0111) + 4) % 8;
            *value ^= (xor_key << rotation) | (xor_key >> rotation);
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
        ($block:expr) => {
            let bytes_read = from
                .read(&mut $block)
                .or(Err(DecryptorError::IOError))?
                .max(bytes_left);

            map.decrypt_block(&mut $block[0..bytes_read]);
            to.write_all(&$block[0..bytes_read])
                .or(Err(DecryptorError::IOError))?;
            bytes_left -= bytes_read;
        };
    }

    // Decrypt the first block
    let mut buffer = [0u8; 0x7FFF];
    decrypt_block!(buffer);

    // Decrypt rest of the blocks
    let mut buffer = [0u8; 0x7FFE];
    while bytes_left > 0 {
        decrypt_block!(buffer);
    }

    Ok(())
}
