use std::io::Write;

use crate::interfaces::decryptor::{DecryptorError, SeekReadable};

pub fn decrypt_map(
    _embed_key: &[u8],
    _trim_right: usize,
    _from: &mut dyn SeekReadable,
    _to: &mut dyn Write,
) -> Result<(), DecryptorError> {
    todo!()
}
