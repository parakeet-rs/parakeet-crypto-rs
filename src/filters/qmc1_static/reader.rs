use std::io::{ErrorKind, Read};

use super::QMC1Static;

pub struct QMC1StaticReader<R>
where
    R: Read,
{
    crypto: QMC1Static,
    reader: R,
}

impl<R> QMC1StaticReader<R>
where
    R: Read,
{
    pub fn new(crypto: QMC1Static, prev_reader: R) -> Self {
        Self {
            crypto,
            reader: prev_reader,
        }
    }
}

impl<R> Read for QMC1StaticReader<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read_amount = self.reader.read(&mut buf[..])?;

        self.crypto
            .transform(&mut buf[..read_amount])
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))
    }
}
