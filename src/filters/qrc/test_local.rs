use super::Qrc;
use crate::filters::{QMC1Static, QMC1StaticReader};
use std::{
    fs::{self, File},
    path::PathBuf,
};

#[test]
fn test_qrc_decode() {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path_qmc1_key = d.join("keys/qmc1_static_key128.bin");
    let path_qrc_keys = d.join("keys/qrc_keys.bin");
    let path_encrypted = d.join("local/Ado - 千本桜 - 241 - 千本桜_qm.qrc");

    assert!(
        path_qmc1_key.exists() && path_qrc_keys.exists() && path_encrypted.exists(),
        "test file does not exist",
    );

    let qmc1_static_key = fs::read(path_qmc1_key).unwrap();
    let qrc_keys = fs::read(path_qrc_keys).unwrap();
    let (key1, key2_3) = qrc_keys.split_at(8);
    let (key2, key3) = key2_3.split_at(8);

    let src = File::open(path_encrypted).unwrap();

    let qmc1 = QMC1StaticReader::new(
        QMC1Static::new(&qmc1_static_key[..].try_into().unwrap()),
        src,
    );

    let mut qrc_reader = Qrc::new(
        key1.try_into().unwrap(),
        key2.try_into().unwrap(),
        key3.try_into().unwrap(),
        qmc1,
    );
    let mut output = vec![0u8; 0];
    std::io::copy(&mut qrc_reader, &mut output).unwrap();
    println!("{}", String::from_utf8(output).unwrap());
}
