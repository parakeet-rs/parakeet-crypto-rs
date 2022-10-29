use std::io::{SeekFrom, Write};

use crate::{
    interfaces::decryptor::{DecryptorError, SeekReadable},
    utils::rc4_qmc2::RC4QMC2,
};

use super::key_utils::{calculate_key_hash, get_segment_key};

const FIRST_SEGMENT_SIZE: usize = 0x0080;
const OTHER_SEGMENT_SIZE: usize = 0x1400;

/// QMC2's RC4 decryption implementation.
/// The file is split into segments:
///   - The first segment (0x80 bytes)
///   - The second segment (0x1400-0x80 bytes, segment_id = 0),
///     where the first 0x80 bytes were discarded.
///   - Rest of the segments (each 0x1400 bytes, segment_id = 1, 2, 3, ...)
struct QMC2RC4 {
    rc4: RC4QMC2,
    key: Box<[u8]>,
    key_hash: u64,
}

impl QMC2RC4 {
    fn new<T: AsRef<[u8]>>(key: T) -> Self {
        let key = key.as_ref();

        Self {
            key: Box::from(key),
            key_hash: calculate_key_hash(key) as u64,
            rc4: RC4QMC2::new(key),
        }
    }

    fn decrypt_first_segment(&self, block: &mut [u8]) {
        let key_size = self.key.len();
        for (i, item) in block.iter_mut().enumerate() {
            let seed = self.key[i % key_size];
            let key_index = get_segment_key(self.key_hash, i as u64, seed as u64);
            *item ^= self.key[key_index % key_size];
        }
    }

    fn decrypt_other_segment(&self, id: usize, block: &mut [u8], extra_discard: usize) {
        let seed = self.key[id & 0x1FF] as u64;
        let discards = get_segment_key(self.key_hash, id as u64, seed) & 0x1FF;

        let mut rc4 = self.rc4.clone();
        rc4.skip(discards + extra_discard);

        for v in block.iter_mut() {
            *v ^= rc4.derive_byte();
        }
    }
}

pub fn decrypt_rc4(
    embed_key: &[u8],
    trim_right: usize,
    from: &mut dyn SeekReadable,
    to: &mut dyn Write,
) -> Result<(), DecryptorError> {
    let decryptor = QMC2RC4::new(embed_key);

    // Detect file size.
    let mut bytes_left = from
        .seek(SeekFrom::End(-(trim_right as i64)))
        .or(Err(DecryptorError::IOError))? as usize;

    // Move back to the beginning of the stream.
    from.seek(SeekFrom::Start(0))
        .or(Err(DecryptorError::IOError))?;

    let mut block_id = 0usize;
    let mut buffer = [0u8; OTHER_SEGMENT_SIZE];

    macro_rules! decrypt_block {
        ($block_len:expr, $decryptor_method:expr) => {
            if bytes_left > 0 {
                let bytes_read = from
                    .read(&mut buffer[..$block_len])
                    .or(Err(DecryptorError::IOError))?
                    .min(bytes_left);

                $decryptor_method(&mut buffer[..bytes_read]);

                to.write_all(&buffer[..bytes_read])
                    .or(Err(DecryptorError::IOError))?;
                bytes_left -= bytes_read;
            }
        };
    }

    macro_rules! decrypt_other_segment {
        ($discards:expr) => {
            decrypt_block!(OTHER_SEGMENT_SIZE - $discards, |buffer| {
                decryptor.decrypt_other_segment(block_id, buffer, $discards);
            });
            block_id += 1;
        };
    }

    // Decrypt first block.
    decrypt_block!(FIRST_SEGMENT_SIZE, |block| {
        decryptor.decrypt_first_segment(block);
    });
    decrypt_other_segment!(FIRST_SEGMENT_SIZE);

    // Decrypt the rest of the blocks.
    while bytes_left > 0 {
        decrypt_other_segment!(0);
    }

    Ok(())
}
