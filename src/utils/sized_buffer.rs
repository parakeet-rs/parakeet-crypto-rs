#[derive(Debug, Clone, Copy)]
pub struct SizedBuffer<const N: usize> {
    buffer: [u8; N],
    size: usize,
}
impl<const N: usize> Default for SizedBuffer<N> {
    fn default() -> Self {
        Self {
            buffer: [0u8; N],
            size: 0,
        }
    }
}

impl<const N: usize> SizedBuffer<N> {
    pub fn consume(&mut self, buf: &mut [u8]) -> usize {
        let process_len = std::cmp::min(buf.len(), self.size);
        if process_len != 0 {
            buf[..process_len].copy_from_slice(&self.buffer[..process_len]);
            self.size -= process_len;
        }
        process_len
    }

    /// Push no more than "N - self.size" bytes to the buffer. Return number of bytes processed.
    pub fn push(&mut self, buf: &[u8]) -> usize {
        let process_len = std::cmp::min(buf.len(), N - self.size);
        self.buffer[self.size..self.size + process_len].copy_from_slice(&buf[..process_len]);
        process_len
    }
}
