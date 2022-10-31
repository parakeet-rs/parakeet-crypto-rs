use md5::{Digest, Md5};

pub fn md5_kugou<T: AsRef<[u8]>>(buffer: T) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(buffer);
    let digest = hasher.finalize();
    let mut result = [0u8; 16];

    for i in (0..16).step_by(2) {
        result[i] = digest[14 - i];
        result[i + 1] = digest[14 - i + 1];
    }

    result
}
