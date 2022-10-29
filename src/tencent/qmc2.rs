use super::qmc_footer_parser::QMCFooterParser;
use crate::interfaces::decryptor::{Decryptor, DecryptorError, SeekReadable};
use std::io::Write;

pub struct QMC2 {
    parser: QMCFooterParser,
}

impl QMC2 {
    pub fn new(parser: QMCFooterParser) -> QMC2 {
        QMC2 { parser }
    }
}

impl Decryptor for QMC2 {
    fn check(&self, from: &mut dyn SeekReadable) -> Result<bool, DecryptorError> {
        self.parser.parse(from).and(Ok(true))
    }

    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn Write,
    ) -> Result<(), DecryptorError> {
        let (trim_right, embed_key) = self.parser.parse(from)?;

        if embed_key.len() <= 300 {
            super::qmc2_decryptor_map::decrypt_map(&embed_key, trim_right, from, to)
        } else {
            super::qmc2_decryptor_rc4::decrypt_rc4(&embed_key, trim_right, from, to)
        }
    }
}
