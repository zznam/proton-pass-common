use credential_exchange_protocol::{ExportRequest, ExportResponse, Version};
use serde::{Deserialize, Serialize};

use super::CxpCredentialType;
use super::CxpError;
use super::archive::{self, CxpArchiveAlgorithm};
use super::hpke::{self, CxpAead};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CxpExchangeMode {
    Direct,
    Indirect,
    #[serde(rename = "self")]
    SelfExchange,
}

#[derive(Serialize)]
struct ExportRequestEnvelope<'a> {
    #[serde(flatten)]
    request: &'a ExportRequest,
    mode: CxpExchangeMode,
    archive: Vec<&'static str>,
}

#[derive(Deserialize)]
pub(crate) struct ParsedExportRequest {
    #[serde(flatten)]
    pub(crate) request: ExportRequest,
    #[allow(dead_code)]
    pub(crate) mode: CxpExchangeMode,
    pub(crate) archive: Vec<String>,
}

#[derive(Serialize)]
struct ExportResponseEnvelope<'a> {
    #[serde(flatten)]
    response: &'a ExportResponse,
    archive: &'static str,
}

#[derive(Deserialize)]
pub(crate) struct ParsedExportResponse {
    #[serde(flatten)]
    pub(crate) response: ExportResponse,
    pub(crate) archive: String,
}

pub(crate) fn build_export_request(
    importer_name: &str,
    credential_types: Vec<CxpCredentialType>,
    public_key: jose_jwk::Jwk,
) -> Result<String, CxpError> {
    let request = ExportRequest {
        version: Version::V0,
        hpke: hpke::offered_parameters(public_key),
        importer: importer_name.to_string(),
        credential_types: if credential_types.is_empty() {
            None
        } else {
            Some(credential_types.into_iter().map(Into::into).collect())
        },
        known_extensions: None,
    };

    let envelope = ExportRequestEnvelope {
        request: &request,
        mode: CxpExchangeMode::Direct,
        archive: archive::supported_algorithms(),
    };

    serde_json::to_string(&envelope)
        .map_err(|e| CxpError::SerializationError(format!("failed to serialize CXP export request: {e}")))
}

pub(crate) fn parse_export_request(request: &str) -> Result<ParsedExportRequest, CxpError> {
    serde_json::from_str(request)
        .map_err(|e| CxpError::DeserializationError(format!("invalid CXP export request: {e}")))
}

pub(crate) fn negotiate_recipient_key(request: &ExportRequest) -> Result<(CxpAead, jose_jwk::Jwk), CxpError> {
    if !matches!(request.version, Version::V0) {
        return Err(CxpError::UnsupportedHpkeParameters(
            "unsupported CXP export request version".to_string(),
        ));
    }

    hpke::negotiate(&request.hpke).ok_or_else(|| {
        CxpError::UnsupportedHpkeParameters("no supported HPKE parameters offered by the peer".to_string())
    })
}

pub(crate) fn build_export_response(
    response: &ExportResponse,
    archive: CxpArchiveAlgorithm,
) -> Result<Vec<u8>, CxpError> {
    let envelope = ExportResponseEnvelope {
        response,
        archive: archive.wire_name(),
    };
    serde_json::to_vec(&envelope)
        .map_err(|e| CxpError::SerializationError(format!("failed to serialize CXP export response: {e}")))
}

pub(crate) fn parse_export_response(response: &[u8]) -> Result<ParsedExportResponse, CxpError> {
    serde_json::from_slice(response)
        .map_err(|e| CxpError::DeserializationError(format!("invalid CXP export response: {e}")))
}

pub(crate) fn validate_export_response(response: &ExportResponse) -> Result<CxpAead, CxpError> {
    if !matches!(response.version, Version::V0) {
        return Err(CxpError::UnsupportedHpkeParameters(
            "unsupported CXP export response version".to_string(),
        ));
    }
    hpke::negotiated_aead(&response.hpke)
}
