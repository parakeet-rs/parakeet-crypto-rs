use std::ops::Rem;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RC4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

pub(crate) fn rc4_init<S: AsMut<[u8]>, K: AsRef<[u8]>>(mut state: S, key: K) {
    let s = state.as_mut();
    let key = key.as_ref();

    let n = s.len();

    for (i, value) in s.iter_mut().enumerate() {
        *value = i as u8;
    }

    let mut j = 0usize;
    for i in 0..n {
        j = j
            .wrapping_add(s[i] as usize)
            .wrapping_add(key[i % key.len()] as usize)
            .rem(n);

        s.swap(i, j);
    }
}

#[allow(dead_code)]
impl RC4 {
    pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
        let mut state = [0; 256];
        rc4_init(&mut state, key);
        Self { state, i: 0, j: 0 }
    }

    #[inline]
    fn derive_from_positions(&mut self, i: u8, j: u8) -> u8 {
        let (i, j) = (i as usize, j as usize);

        self.state.swap(i, j);
        let final_index = self.state[i].wrapping_add(self.state[j]);
        self.state[final_index as usize]
    }

    #[inline]
    pub fn derive_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.derive_from_positions(self.i, self.j)
    }

    pub fn derive_byte_netease(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        let j = self.state[self.i as usize].wrapping_add(self.i);

        self.derive_from_positions(self.i, j)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4() {
        let rc4 = RC4::new(b"this is a test key");

        #[allow(clippy::redundant_clone)]
        let mut rc4_copy = rc4.clone();

        let mut data = vec![0u8; 0];
        for byte in b"hello world".iter() {
            let value = rc4_copy.derive_byte();
            data.push(value ^ byte);
        }

        assert_ne!(rc4.state, rc4_copy.state);
        assert_eq!(data, b"\x07\xb9\x45\x7d\x53\x40\xf8\x6b\x37\x41\x75")
    }
}
