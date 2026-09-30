use proton_pass_common::gunzip::{GunzipError as CommonGunzipError, gunzip as common_gunzip};

#[derive(Debug, proton_pass_derive::Error, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum GunzipError {
    Decompress(String),
    OutputTooBig,
}

impl From<CommonGunzipError> for GunzipError {
    fn from(value: CommonGunzipError) -> Self {
        match value {
            CommonGunzipError::Decompress(msg) => Self::Decompress(msg),
            CommonGunzipError::OutputTooBig => Self::OutputTooBig,
        }
    }
}

#[derive(uniffi::Object)]
pub struct PassGzip;

#[uniffi::export]
impl PassGzip {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn gunzip(&self, input: Vec<u8>) -> Result<Vec<u8>, GunzipError> {
        common_gunzip(&input).map_err(|e| e.into())
    }
}
