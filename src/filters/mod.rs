mod kugou;
pub use kugou::{
    file_constants, file_header, KGMCrypto, KGMCryptoConfig, KugouDecryptReader, KugouEncryptReader,
};

mod qmc1_static;
pub use qmc1_static::{QMC1Static, QMC1StaticReader};

mod qmc2;
pub use qmc2::*;

mod qmc2_map;
pub use qmc2_map::QMC2Map;

mod qmc2_rc4;
pub use qmc2_rc4::QMC2RC4;

mod qrc;

mod ximalaya;
pub use ximalaya::{create_scramble_key, XimalayaCrypto, XimalayaReader, SCRAMBLE_HEADER_LEN};
