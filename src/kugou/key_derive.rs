pub trait KGMDecryptor {
    fn expand_key_slot_key(&mut self, input: &[u8]);
    fn expand_file_key(&mut self, input: &[u8]);
    fn decrypt_block(&mut self, offset: u64, buffer: &mut [u8]);
}
