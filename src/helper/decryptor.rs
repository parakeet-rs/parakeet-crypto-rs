use std::io::{Read, Seek, Write};

use crate::interfaces::decryptor::{Decryptor, DecryptorError};

/// Check and decrypt from an input to an output stream.
/// If the decryptor does not work, it will forward the error from detector
///   or the decryptor.
pub fn check_and_decrypt<R, W>(
    decryptor: impl Decryptor,
    input: &mut R,
    output: &mut W,
) -> Result<(), DecryptorError>
where
    R: Read + Seek,
    W: Write,
{
    decryptor.check(input)?;
    decryptor.decrypt(input, output)?;

    Ok(())
}
