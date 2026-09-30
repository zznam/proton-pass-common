use flate2::read::GzDecoder;
use std::io::Read;

const MAX_OUTPUT_SIZE: u64 = 10 * 1024 * 1024;

#[derive(Debug)]
pub enum GunzipError {
    Decompress(String),
    OutputTooBig,
}

impl std::fmt::Display for GunzipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GunzipError::Decompress(msg) => write!(f, "Decompression error: {msg}"),
            GunzipError::OutputTooBig => write!(f, "Decompressed data too big. Max size allowed: {MAX_OUTPUT_SIZE}"),
        }
    }
}

impl std::error::Error for GunzipError {}

pub fn gunzip(input: &[u8]) -> Result<Vec<u8>, GunzipError> {
    let mut output = Vec::new();
    GzDecoder::new(input)
        .take(MAX_OUTPUT_SIZE + 1)
        .read_to_end(&mut output)
        .map_err(|e| GunzipError::Decompress(e.to_string()))?;
    if output.len() as u64 > MAX_OUTPUT_SIZE {
        return Err(GunzipError::OutputTooBig);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    #[test]
    fn roundtrip() {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"hello world").unwrap();
        let compressed = enc.finish().unwrap();
        assert_eq!(gunzip(&compressed).unwrap(), b"hello world");
    }

    #[test]
    fn invalid_input() {
        assert!(matches!(gunzip(b"not gzip"), Err(GunzipError::Decompress(_))));
    }
}
