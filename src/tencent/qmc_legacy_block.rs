use std::io::{Read, Seek, SeekFrom, Write};

use crate::interfaces::decryptor::DecryptorError;

pub trait QMCLegacyBlockDecryptor {
    fn decrypt_block(&self, block: &mut [u8], offset: usize);
}

#[inline]
pub fn qmc_legacy_decrypt_stream<D, R, W>(
    trim_right: usize,
    decryptor: &D,
    from: &mut R,
    to: &mut W,
) -> Result<(), DecryptorError>
where
    D: QMCLegacyBlockDecryptor,
    R: Read + Seek,
    W: Write,
{
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

                decryptor.decrypt_block(&mut $block[0..bytes_read], $offset);
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
