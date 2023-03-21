use std::io::{ErrorKind, Read};

use crate::{interfaces::DecryptorError, utils::SizedBuffer};

use super::des_impl::Des;

pub struct QrcDesReader<R>
where
    R: Read,
{
    crypto: Des,
    reader: R,

    downstream_buffer: SizedBuffer<8>,
}

impl<R> QrcDesReader<R>
where
    R: Read,
{
    pub fn new(crypto: Des, prev_reader: R) -> Self {
        Self {
            crypto,
            reader: prev_reader,
            downstream_buffer: SizedBuffer::default(),
        }
    }
}

impl<R> Read for QrcDesReader<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut buf = buf;
        let mut bytes_written = 0usize;
        {
            let bytes_consumed = self.downstream_buffer.consume(buf);
            bytes_written += bytes_consumed;
            buf = &mut buf[bytes_consumed..];
        }

        if buf.len() > 8 {
            let last_index = buf.len() - buf.len() % 8;

            let (buf_in_blocks, rest_buf) = buf.split_at_mut(last_index);
            buf = rest_buf;

            let bytes_read = self.reader.read(buf_in_blocks)?;
            bytes_written += bytes_read;
            self.crypto
                .transform_bytes(&mut buf_in_blocks[..bytes_read])
                .ok_or_else(|| {
                    std::io::Error::new(ErrorKind::Other, DecryptorError::QrcDesblockAlignment)
                })?;

            // Did we finish early?
            if bytes_read != buf_in_blocks.len() {
                return Ok(bytes_written);
            }
        }

        if !buf.is_empty() {
            let mut block = [0u8; 8];
            self.reader.read_exact(&mut block).map_err(|_| {
                std::io::Error::new(ErrorKind::Other, DecryptorError::QrcDesblockAlignment)
            })?;
            bytes_written += buf.len();
            self.crypto.transform_bytes(&mut block);
            let (to_copy, to_downstream) = block.split_at(buf.len());
            buf.copy_from_slice(to_copy);
            self.downstream_buffer.push(to_downstream);
        }

        Ok(bytes_written)
    }
}
