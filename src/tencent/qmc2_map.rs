use std::io::{SeekFrom, Write};

use crate::interfaces::decryptor::{DecryptorError, SeekReadable};

struct QMC2Map<'a> {
    key: &'a [u8],
    table: [u8; 0x8000],
}

impl QMC2Map<'_> {
    fn new(key: &[u8]) -> QMC2Map {
        // Derive cache table from key.
        let key_len = key.len() as u32;
        let mut table = [0u8; 0x8000];

        for (i, v) in table.iter_mut().enumerate() {
            let offset = i as u32;
            *v = offset
                .wrapping_mul(offset)
                .wrapping_add(71214)
                .wrapping_rem(key_len) as u8;
        }

        QMC2Map { key, table }
    }

    #[inline]
    fn get_xor_value(&self, offset: usize) -> u8 {
        let key = self.table[offset];
        let xor_key = self.key[key as usize];
        let rotation = ((key & 0b0111) + 4) % 8;
        (xor_key << rotation) | (xor_key >> rotation)
    }

    /// Decrypt a block.
    /// `offset` is the offset of the block (0~0x7fff)
    #[inline]
    fn decrypt_block(&self, block: &mut [u8], offset: usize) {
        debug_assert!(
            block.len() <= self.table.len(),
            "block size should not exceed table size"
        );

        for (i, value) in block.iter_mut().enumerate() {
            *value ^= self.get_xor_value(i + offset);
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
