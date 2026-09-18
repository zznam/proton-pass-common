use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

use super::CxpError;

const MAX_DECOMPRESSED_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CxpArchiveAlgorithm {
    Deflate,
}

impl CxpArchiveAlgorithm {
    pub(crate) const WIRE_NAME: &'static str = "deflate";

    fn from_wire_name(name: &str) -> Option<Self> {
        (name == Self::WIRE_NAME).then_some(Self::Deflate)
    }

    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            Self::Deflate => Self::WIRE_NAME,
        }
    }
}

pub(crate) fn supported_algorithms() -> Vec<&'static str> {
    vec![CxpArchiveAlgorithm::WIRE_NAME]
}

pub(crate) fn negotiate(offered: &[String]) -> Result<CxpArchiveAlgorithm, CxpError> {
    offered
        .iter()
        .find_map(|name| CxpArchiveAlgorithm::from_wire_name(name))
        .ok_or_else(|| CxpError::UnsupportedArchiveAlgorithm("no supported archive algorithm was offered".to_string()))
}

pub(crate) fn parse_selected(name: &str) -> Result<CxpArchiveAlgorithm, CxpError> {
    CxpArchiveAlgorithm::from_wire_name(name)
        .ok_or_else(|| CxpError::UnsupportedArchiveAlgorithm(format!("unsupported archive algorithm: {name}")))
}

pub(crate) fn compress(algorithm: CxpArchiveAlgorithm, data: &[u8]) -> Result<Vec<u8>, CxpError> {
    match algorithm {
        CxpArchiveAlgorithm::Deflate => {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| CxpError::EncryptionError(format!("failed to compress CXP payload: {e}")))?;
            encoder
                .finish()
                .map_err(|e| CxpError::EncryptionError(format!("failed to compress CXP payload: {e}")))
        }
    }
}

pub(crate) fn decompress(algorithm: CxpArchiveAlgorithm, data: &[u8]) -> Result<Vec<u8>, CxpError> {
    match algorithm {
        CxpArchiveAlgorithm::Deflate => deflate_decompress_with_limit(data, MAX_DECOMPRESSED_SIZE),
    }
}

fn deflate_decompress_with_limit(data: &[u8], limit: u64) -> Result<Vec<u8>, CxpError> {
    let mut decoder = DeflateDecoder::new(data).take(limit + 1);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| CxpError::DecryptionError(format!("failed to decompress CXP payload: {e}")))?;
    if out.len() as u64 > limit {
        return Err(CxpError::DecryptionError(format!(
            "decompressed CXP payload exceeds the {limit}-byte limit"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflate_round_trips() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(10);
        let compressed = compress(CxpArchiveAlgorithm::Deflate, &data).unwrap();
        let decompressed = decompress(CxpArchiveAlgorithm::Deflate, &compressed).unwrap();
        assert_eq!(decompressed, data);
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn negotiate_picks_the_first_mutually_supported_algorithm() {
        let picked = negotiate(&["zip".to_string(), "deflate".to_string()]).unwrap();
        assert_eq!(picked, CxpArchiveAlgorithm::Deflate);
    }

    #[test]
    fn negotiate_fails_when_nothing_is_shared() {
        assert!(negotiate(&[]).is_err());
        assert!(negotiate(&["zip".to_string()]).is_err());
    }

    #[test]
    fn parse_selected_rejects_unknown_algorithms() {
        assert!(parse_selected("deflate").is_ok());
        assert!(parse_selected("zip").is_err());
    }

    #[test]
    fn corrupted_compressed_data_fails_cleanly() {
        assert!(decompress(CxpArchiveAlgorithm::Deflate, &[1, 2, 3, 4]).is_err());
    }

    #[test]
    fn decompression_beyond_the_limit_is_rejected() {
        let data = vec![0u8; 1024];
        let compressed = compress(CxpArchiveAlgorithm::Deflate, &data).unwrap();
        assert!(deflate_decompress_with_limit(&compressed, 1023).is_err());
        assert!(deflate_decompress_with_limit(&compressed, 1024).is_ok());
    }
}
