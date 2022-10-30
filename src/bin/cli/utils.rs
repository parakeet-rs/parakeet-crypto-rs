use std::{fs, path::Path};

pub fn read_key_from_parameter(value: &str) -> Option<Box<[u8]>> {
    if let Some(value) = value.strip_prefix('@') {
        let file_content = fs::read(Path::new(value)).unwrap();
        Some(file_content.into())
    } else if let Some(value) = value.strip_prefix("base64:") {
        let content = base64::decode(&value).unwrap();
        Some(content.into())
    } else {
        None
    }
}
