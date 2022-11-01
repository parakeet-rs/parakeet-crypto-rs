use md5::{Digest, Md5};

pub fn md5<T: AsRef<[u8]>>(buffer: T) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(buffer);
    let digest = hasher.finalize();

    let mut result = [0u8; 16];
    result.copy_from_slice(&digest);
    result
}
