use super::{data, int_helper};

type DesSubkeys = [u64; 16];

/// QRC's modified DES implementation
#[derive(Debug, Default, Clone, Copy)]
pub struct Des {
    subkeys: DesSubkeys,
}

fn des_ip(data: u64) -> u64 {
    int_helper::map_u64_bits(data, &data::IP)
}

fn des_ip_inv(data: u64) -> u64 {
    int_helper::map_u64_bits(data, &data::IP_INV)
}

fn sbox_transform(state: u64) -> u32 {
    const LARGE_STATE_SHIFTS: [u8; 8] = [26, 20, 14, 8, 58, 52, 46, 40];

    data::SBOXES
        .iter()
        .zip(LARGE_STATE_SHIFTS)
        .fold(0u32, |next, (sbox, large_state_shift)| {
            let sbox_idx = (state >> large_state_shift) & 0b111111;
            (next << 4) | (sbox[sbox_idx as usize] as u32)
        })
}

fn des_crypt_proc(state: u64, key: &u64) -> u64 {
    let mut state = state;
    let state_hi32 = int_helper::u64_get_hi32(state);
    let state_lo32 = int_helper::u64_get_lo32(state);

    state = int_helper::map_2_u32_bits_to_u64(
        state_hi32,
        &data::KEY_EXPANSION_PART1,
        state_hi32,
        &data::KEY_EXPANSION_PART2,
    );
    state ^= key;

    let mut next_lo32 = sbox_transform(state);
    next_lo32 = int_helper::map_u32_bits(next_lo32, &data::PBOX);
    next_lo32 ^= state_lo32;

    // make u64, then swap
    //   => make reverted u64
    // return swap_u64_side(int_helper::make_u64(state_hi32, next_lo32));
    int_helper::make_u64(next_lo32, state_hi32)
}

impl Des {
    pub fn new(key: &[u8; 8]) -> Self {
        let mut result = Self::default();
        result.set_key(key);
        result
    }

    pub fn set_key(&mut self, key: &[u8; 8]) {
        let key = u64::from_le_bytes(*key);

        let mut param_c = int_helper::map_u64_to_u32_bits(key, &data::KEY_PERMUTATION_C);
        let mut param_d = int_helper::map_u64_to_u32_bits(key, &data::KEY_PERMUTATION_D);

        for (subkey, shift_left) in self.subkeys.iter_mut().zip(data::KEY_RND_SHIFTS) {
            let shift_right = 28 - shift_left;
            param_c = (param_c << shift_left) | ((param_c >> shift_right) & 0xFFFFFFF0); // rotate 28 bit int
            param_d = (param_d << shift_left) | ((param_d >> shift_right) & 0xFFFFFFF0);
            *subkey = int_helper::map_2_u32_bits_to_u64(
                param_c,
                &data::KEY_COMPRESSION_PART1,
                param_d,
                &data::KEY_COMPRESSION_PART2,
            );
        }
    }

    pub fn crypt_block<const IS_ENCRYPT: bool>(&self, data: u64) -> u64 {
        let mut state = des_ip(data);

        state = if IS_ENCRYPT {
            self.subkeys.iter().rev().fold(state, des_crypt_proc)
        } else {
            self.subkeys.iter().fold(state, des_crypt_proc)
        };

        // Swap data hi32/lo32
        state = int_helper::swap_u64_side(state);

        // Final permutation
        state = des_ip_inv(state);

        state
    }

    pub fn crypt_block_bytes<const IS_ENCRYPT: bool>(&self, data: &mut [u8]) -> Option<()> {
        if data.len() % 8 == 0 {
            for i in (0..data.len()).step_by(8) {
                let block = &mut data[i..i + 8];
                let value = u64::from_le_bytes(block.try_into().unwrap());
                let transformed = self.crypt_block::<IS_ENCRYPT>(value);
                block.copy_from_slice(&transformed.to_le_bytes());
            }
            Some(())
        } else {
            None
        }
    }

    pub fn encrypt_bytes(&self, data: &mut [u8]) -> Option<()> {
        self.crypt_block_bytes::<true>(data)
    }

    pub fn decrypt_bytes(&self, data: &mut [u8]) -> Option<()> {
        self.crypt_block_bytes::<false>(data)
    }
}

#[test]
fn test_des_encrypt() {
    let mut input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];
    let expected_data = [
        0xFD, 0x0E, 0x64, 0x06, 0x65, 0xBE, 0x74, 0x13, //
        0x77, 0x63, 0x3B, 0x02, 0x45, 0x4E, 0x70, 0x7A, //
    ];

    let des = Des::new(b"TEST!KEY");
    des.encrypt_bytes(&mut input).unwrap();
    assert_eq!(input, expected_data);
}

#[test]
fn test_des_decrypt() {
    let mut input = [
        0xFD, 0x0E, 0x64, 0x06, 0x65, 0xBE, 0x74, 0x13, //
        0x77, 0x63, 0x3B, 0x02, 0x45, 0x4E, 0x70, 0x7A, //
    ];
    let expected_data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];

    let des = Des::new(b"TEST!KEY");
    des.decrypt_bytes(&mut input).unwrap();
    assert_eq!(input, expected_data);
}
