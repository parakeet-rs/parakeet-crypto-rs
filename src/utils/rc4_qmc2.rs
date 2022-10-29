use std::ops::Rem;

use super::rc4::rc4_init;

/// A strange variation of RC4 implementation used in QMC2.
/// QMC2 所使用的一种「魔改」RC4 实现。
#[derive(Clone)]
pub struct RC4QMC2 {
    state: Vec<u8>,
    i: usize,
    j: usize,
}

impl RC4QMC2 {
    #[inline(always)]
    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        let n = key.as_ref().len();
        let mut state = vec![0u8; n];
        rc4_init(&mut state, key);

        Self { state, i: 0, j: 0 }
    }

    pub fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.derive_byte();
        }
    }

    pub fn derive_byte(&mut self) -> u8 {
        let n = self.state.len();
        self.i = self.i.wrapping_add(1).rem(n);
        self.j = self
            .j
            .wrapping_add(self.state[self.i as usize] as usize)
            .rem(n);

        self.state.swap(self.i, self.j);
        let final_index = (self.state[self.i] as usize)
            .wrapping_add(self.state[self.j] as usize)
            .rem(n);
        self.state[final_index as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4() {
        let rc4 = RC4QMC2::new(b"this is a test key");

        #[allow(clippy::redundant_clone)]
        let mut rc4_copy = rc4.clone();

        let mut data = vec![0u8; 0];
        for byte in b"hello world".iter() {
            let value = rc4_copy.derive_byte();
            data.push(value ^ byte);
        }

        assert_ne!(rc4.state, rc4_copy.state);
        assert_eq!(data, b"\x68\x75\x6b\x64\x64\x24\x7f\x60\x7c\x7d\x60")
    }
}
