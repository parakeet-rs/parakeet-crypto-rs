pub trait KGMCrypto {
    fn expand_slot_key(&mut self, input: &[u8]);
    fn expand_file_key(&mut self, input: &[u8]);
    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]);
    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]);
}