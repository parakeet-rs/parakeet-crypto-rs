use std::io::Read;

use flate2::read::ZlibDecoder;

use super::des::{DESMode, Des, QrcDesReader};

pub struct Qrc<R>
where
    R: Read,
{
    reader: ZlibDecoder<QrcDesReader<QrcDesReader<QrcDesReader<R>>>>,
}

impl<R> Qrc<R>
where
    R: Read,
{
    pub fn new(key1: &[u8; 8], key2: &[u8; 8], key3: &[u8; 8], prev_reader: R) -> Qrc<R> {
        let mut r = prev_reader;
        let mut temp = [0u8; 11];
        r.read_exact(&mut temp).unwrap();
        println!("{}", String::from_utf8(temp.into()).unwrap());

        let r1 = QrcDesReader::new(Des::new(key1, DESMode::Decrypt), r);
        let r2 = QrcDesReader::new(Des::new(key2, DESMode::Encrypt), r1);
        let r3 = QrcDesReader::new(Des::new(key3, DESMode::Decrypt), r2);
        Self {
            reader: ZlibDecoder::new(r3),
        }
    }
}

impl<R> Read for Qrc<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}
