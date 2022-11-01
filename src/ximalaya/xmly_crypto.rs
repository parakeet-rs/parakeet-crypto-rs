#[derive(Debug, Clone, Copy)]
struct XmlyCrypto<const KEY_SIZE: usize> {
    crypto_key: [u8; KEY_SIZE],
    scramble_table: [usize; 1024],
}

impl<const KEY_SIZE: usize> Default for XmlyCrypto<KEY_SIZE> {
    fn default() -> Self {
        Self {
            crypto_key: [0; KEY_SIZE],
            scramble_table: [0; 1024],
        }
    }
}

impl<const KEY_SIZE: usize> XmlyCrypto<KEY_SIZE> {
    fn decrypt_header(&self, &buffer: &[u8; 1024]) -> [u8; 1024] {
        let mut result = buffer;

        for (key_index, &i) in self.scramble_table.iter().enumerate() {
            result[i] = buffer[i] ^ self.crypto_key[key_index % self.crypto_key.len()]
        }

        result
    }
}
