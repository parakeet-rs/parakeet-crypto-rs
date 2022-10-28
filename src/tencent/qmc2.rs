use super::qmc_footer_parser::QMCFooterParser;
use crate::interfaces::decryptor::{Decryptor, DecryptorError, SeekReadable};
use std::io::Write;

pub struct QMC2 {
    parser: QMCFooterParser,
}

impl Decryptor for QMC2 {
    fn check(&self, from: &mut dyn SeekReadable) -> Result<bool, DecryptorError> {
        self.parser.parse(from);

        Ok(true)
    }

    fn decrypt(
        &self,
        from: &mut dyn SeekReadable,
        to: &mut dyn Write,
    ) -> Result<(), DecryptorError> {
        Ok(())
    }
}
