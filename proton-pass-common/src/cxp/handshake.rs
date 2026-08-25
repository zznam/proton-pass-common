use credential_exchange_protocol::{ExportRequest, ExportResponse, Version};

use super::CxpError;
use super::{CxpCredentialType, hpke};

pub(crate) fn build_export_request(
    importer_name: &str,
    credential_types: Vec<CxpCredentialType>,
    public_key: jose_jwk::Jwk,
) -> ExportRequest {
    ExportRequest {
        version: Version::V0,
        hpke: vec![hpke::supported_parameters(Some(public_key))],
        importer: importer_name.to_string(),
        credential_types: if credential_types.is_empty() {
            None
        } else {
            Some(credential_types.into_iter().map(Into::into).collect())
        },
        known_extensions: None,
    }
}

pub(crate) fn parse_export_request(request: &str) -> Result<ExportRequest, CxpError> {
    serde_json::from_str(request)
        .map_err(|e| CxpError::DeserializationError(format!("invalid CXP export request: {e}")))
}

pub(crate) fn negotiate_recipient_key(request: &ExportRequest) -> Result<jose_jwk::Jwk, CxpError> {
    if !matches!(request.version, Version::V0) {
        return Err(CxpError::UnsupportedHpkeParameters(
            "unsupported CXP export request version".to_string(),
        ));
    }

    request
        .hpke
        .iter()
        .find(|params| hpke::is_supported(params))
        .and_then(|params| params.key.clone())
        .ok_or_else(|| {
            CxpError::UnsupportedHpkeParameters("no supported HPKE parameters offered by the peer".to_string())
        })
}

pub(crate) fn parse_export_response(response: &[u8]) -> Result<ExportResponse, CxpError> {
    serde_json::from_slice(response)
        .map_err(|e| CxpError::DeserializationError(format!("invalid CXP export response: {e}")))
}

pub(crate) fn validate_export_response(response: &ExportResponse) -> Result<(), CxpError> {
    if !matches!(response.version, Version::V0) {
        return Err(CxpError::UnsupportedHpkeParameters(
            "unsupported CXP export response version".to_string(),
        ));
    }
    if hpke::is_supported(&response.hpke) {
        Ok(())
    } else {
        Err(CxpError::UnsupportedHpkeParameters(
            "the responder used HPKE parameters that were never offered".to_string(),
        ))
    }
}
