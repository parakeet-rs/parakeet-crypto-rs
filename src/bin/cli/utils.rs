use std::{fs, path::Path};

use argh::FromArgValue;
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};

pub fn read_key_from_parameter(value: &str) -> Option<Box<[u8]>> {
    if let Some(value) = value.strip_prefix('@') {
        let file_content = fs::read(Path::new(value)).unwrap();
        Some(file_content.into())
    } else if let Some(value) = value.strip_prefix("base64:") {
        let content = Base64.decode(value).unwrap();
        Some(content.into())
    } else {
        None
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CliBinaryContent {
    pub content: Box<[u8]>,
}

impl FromArgValue for CliBinaryContent {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        if let Some(parsed) = read_key_from_parameter(value) {
            Ok(Self { content: parsed })
        } else {
            Err(String::from("could not parse"))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CliBinaryArray<const SIZE: usize> {
    pub content: [u8; SIZE],
}

impl<const SIZE: usize> FromArgValue for CliBinaryArray<SIZE> {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        if let Some(parsed) = read_key_from_parameter(value) {
            if parsed.len() == SIZE {
                let mut buffer = [0u8; SIZE];
                buffer.copy_from_slice(&parsed);
                Ok(Self { content: buffer })
            } else {
                Err(format!(
                    "parameter size mismatch, expected {} bytes, got {}",
                    SIZE,
                    parsed.len()
                ))
            }
        } else {
            Err(String::from("could not binary data"))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CliFilePath {
    pub path: Box<Path>,
}

impl FromArgValue for CliFilePath {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        Ok(Self {
            path: Box::from(Path::new(value)),
        })
    }
}
