mod handshake;
mod hpke;

use crate::cxf::{CxfError, CxfExportInput, CxfImportResult, CxfWarning};
use credential_exchange_protocol::{CredentialType, ExportResponse, Version};
use parking_lot::Mutex;
use proton_pass_derive::{Error, ffi_error};
use proton_pass_types::ItemContent;
use zeroize::Zeroizing;

#[proton_pass_derive::ffi_type]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CxpCredentialType {
    BasicAuth,
    Passkey,
    Totp,
    Note,
    File,
    Address,
    CreditCard,
    DriverLicense,
    ItemReference,
    IdentityDocument,
    Passport,
    PersonName,
    SshKey,
    ApiKey,
}

impl From<CxpCredentialType> for CredentialType {
    fn from(value: CxpCredentialType) -> Self {
        match value {
            CxpCredentialType::BasicAuth => CredentialType::BasicAuth,
            CxpCredentialType::Passkey => CredentialType::Passkey,
            CxpCredentialType::Totp => CredentialType::Totp,
            CxpCredentialType::Note => CredentialType::Note,
            CxpCredentialType::File => CredentialType::File,
            CxpCredentialType::Address => CredentialType::Address,
            CxpCredentialType::CreditCard => CredentialType::CreditCard,
            CxpCredentialType::DriverLicense => CredentialType::DriverLicense,
            CxpCredentialType::ItemReference => CredentialType::ItemReference,
            CxpCredentialType::IdentityDocument => CredentialType::IdentityDocument,
            CxpCredentialType::Passport => CredentialType::Passport,
            CxpCredentialType::PersonName => CredentialType::PersonName,
            CxpCredentialType::SshKey => CredentialType::SshKey,
            CxpCredentialType::ApiKey => CredentialType::ApiKey,
        }
    }
}

impl CxpCredentialType {
    fn from_upstream(value: &CredentialType) -> Option<Self> {
        Some(match value {
            CredentialType::BasicAuth => CxpCredentialType::BasicAuth,
            CredentialType::Passkey => CxpCredentialType::Passkey,
            CredentialType::Totp => CxpCredentialType::Totp,
            CredentialType::Note => CxpCredentialType::Note,
            CredentialType::File => CxpCredentialType::File,
            CredentialType::Address => CxpCredentialType::Address,
            CredentialType::CreditCard => CxpCredentialType::CreditCard,
            CredentialType::DriverLicense => CxpCredentialType::DriverLicense,
            CredentialType::ItemReference => CxpCredentialType::ItemReference,
            CredentialType::IdentityDocument => CxpCredentialType::IdentityDocument,
            CredentialType::Passport => CxpCredentialType::Passport,
            CredentialType::PersonName => CxpCredentialType::PersonName,
            CredentialType::SshKey => CxpCredentialType::SshKey,
            CredentialType::ApiKey => CxpCredentialType::ApiKey,
            CredentialType::Unknown(_) => return None,
        })
    }
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxpExportRequestSummary {
    pub importer_name: String,
    pub requested_credential_types: Vec<CxpCredentialType>,
    pub requests_all_credential_types: bool,
}

#[proton_pass_derive::ffi_type]
#[derive(Debug, PartialEq, Eq)]
pub struct CxpExportRequest {
    pub importer_name: String,
    pub supported_credential_types: Vec<CxpCredentialType>,
}

#[ffi_error]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CxpError {
    SerializationError(String),
    DeserializationError(String),
    UnsupportedHpkeParameters(String),
    EncryptionError(String),
    DecryptionError(String),
    InvalidState(String),
}

struct CxpExportEnvelope {
    ephemeral_private_key: Zeroizing<Vec<u8>>,
    importer_name: String,
    request: String,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxpExportResponse {
    pub response: Vec<u8>,
    pub warnings: Vec<CxfWarning>,
}

fn begin_cxp_export(request: CxpExportRequest) -> Result<(String, CxpExportEnvelope), CxpError> {
    let keypair = hpke::generate_keypair();
    let export_request = handshake::build_export_request(
        &request.importer_name,
        request.supported_credential_types,
        keypair.public_jwk,
    );
    let serialized = serde_json::to_string(&export_request)
        .map_err(|e| CxpError::SerializationError(format!("failed to serialize CXP export request: {e}")))?;

    Ok((
        serialized.clone(),
        CxpExportEnvelope {
            ephemeral_private_key: keypair.private_key,
            importer_name: request.importer_name,
            request: serialized,
        },
    ))
}

fn credential_types_for_item(content: &ItemContent) -> Vec<CxpCredentialType> {
    match content {
        ItemContent::Login(login) => {
            let mut types = vec![CxpCredentialType::BasicAuth];
            if !login.passkeys.is_empty() {
                types.push(CxpCredentialType::Passkey);
            }
            if !login.totp_uri.is_empty() {
                types.push(CxpCredentialType::Totp);
            }
            types
        }
        ItemContent::Note(_) => vec![CxpCredentialType::Note],
        ItemContent::CreditCard(_) => vec![CxpCredentialType::CreditCard],
        ItemContent::SshKey(_) => vec![CxpCredentialType::SshKey],
        ItemContent::Identity(_) => vec![
            CxpCredentialType::PersonName,
            CxpCredentialType::Address,
            CxpCredentialType::IdentityDocument,
            CxpCredentialType::Passport,
            CxpCredentialType::DriverLicense,
        ],
        ItemContent::Alias(_) | ItemContent::Wifi(_) | ItemContent::Custom(_) => Vec::new(),
    }
}

fn filter_export_input_by_requested_types(export: &mut CxfExportInput, requested: &[CxpCredentialType]) {
    for vault in &mut export.vaults {
        vault.items.retain(|item| {
            credential_types_for_item(&item.item.content)
                .iter()
                .any(|t| requested.contains(t))
        });
    }
}

fn summarize_export_request(request: &str) -> Result<CxpExportRequestSummary, CxpError> {
    let parsed_request = handshake::parse_export_request(request)?;
    let requested_credential_types = parsed_request
        .credential_types
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(CxpCredentialType::from_upstream)
        .collect();

    Ok(CxpExportRequestSummary {
        importer_name: parsed_request.importer,
        requested_credential_types,
        requests_all_credential_types: parsed_request.credential_types.is_none(),
    })
}

fn respond_to_cxp_export(request: &str, mut export: CxfExportInput) -> Result<CxpExportResponse, CxpError> {
    let parsed_request = handshake::parse_export_request(request)?;
    let recipient_key = handshake::negotiate_recipient_key(&parsed_request)?;

    if let Some(credential_types) = &parsed_request.credential_types {
        let requested: Vec<CxpCredentialType> = credential_types
            .iter()
            .filter_map(CxpCredentialType::from_upstream)
            .collect();
        filter_export_input_by_requested_types(&mut export, &requested);
    }

    let exporter_name = export.exporter_display_name.clone();
    let cxf_result = crate::cxf::export_cxf(export).map_err(|e| CxpError::SerializationError(format!("{e}")))?;

    let sealed = hpke::seal(
        &recipient_key,
        parsed_request.importer.as_bytes(),
        request.as_bytes(),
        cxf_result.payload.as_bytes(),
    )?;

    let response = ExportResponse {
        version: Version::V0,
        hpke: hpke::supported_parameters(Some(sealed.encapped_key_jwk)),
        exporter: exporter_name,
        payload: sealed.ciphertext.into(),
    };

    let response = serde_json::to_vec(&response)
        .map_err(|e| CxpError::SerializationError(format!("failed to serialize CXP export response: {e}")))?;

    Ok(CxpExportResponse {
        response,
        warnings: cxf_result.warnings,
    })
}

fn complete_cxp_export(envelope: CxpExportEnvelope, encrypted_response: &[u8]) -> Result<CxfImportResult, CxpError> {
    let response = handshake::parse_export_response(encrypted_response)?;
    handshake::validate_export_response(&response)?;
    let encapped_key = response.hpke.key.clone().ok_or_else(|| {
        CxpError::UnsupportedHpkeParameters("CXP export response is missing the encapsulated key".to_string())
    })?;

    let mut plaintext = hpke::open(
        &envelope.ephemeral_private_key,
        &encapped_key,
        envelope.importer_name.as_bytes(),
        envelope.request.as_bytes(),
        response.payload.as_ref(),
    )?;

    let payload = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *plaintext))
            .map_err(|e| CxpError::DeserializationError(format!("decrypted CXP payload was not valid UTF-8: {e}")))?,
    );

    crate::cxf::import_cxf(&payload).map_err(|e: CxfError| CxpError::DeserializationError(format!("{e}")))
}

#[derive(Default)]
pub struct CxpImportHandler {
    pending: Mutex<Option<CxpExportEnvelope>>,
}

impl CxpImportHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_export_request(&self, request: CxpExportRequest) -> Result<String, CxpError> {
        let (serialized, envelope) = begin_cxp_export(request)?;
        *self.pending.lock() = Some(envelope);
        Ok(serialized)
    }

    pub fn process_export_response(&self, encrypted_response: &[u8]) -> Result<CxfImportResult, CxpError> {
        let envelope = self.pending.lock().take().ok_or_else(|| {
            CxpError::InvalidState("create_export_request must be called before process_export_response".to_string())
        })?;
        complete_cxp_export(envelope, encrypted_response)
    }
}

#[derive(Default)]
pub struct CxpExportHandler;

impl CxpExportHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn create_export_response(&self, request: &str, export: CxfExportInput) -> Result<CxpExportResponse, CxpError> {
        respond_to_cxp_export(request, export)
    }

    pub fn parse_export_request(&self, request: &str) -> Result<CxpExportRequestSummary, CxpError> {
        summarize_export_request(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxf::{CxfVaultWithItems, ItemMetadata, ItemWithMetadata};
    use proton_pass_types::{ItemContent, ItemData, LoginItem, VaultData, VaultDisplayPreferences};

    fn sample_export_input() -> CxfExportInput {
        let login = LoginItem {
            email: "alice@example.com".to_string(),
            username: String::new(),
            password: "hunter2".to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let item = ItemData::new(
            "My login".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(login),
            Vec::new(),
        )
        .unwrap();
        let vault = VaultData::new(
            "Personal".to_string(),
            String::new(),
            VaultDisplayPreferences::default(),
        )
        .unwrap();

        CxfExportInput {
            vaults: vec![CxfVaultWithItems {
                vault,
                items: vec![ItemWithMetadata {
                    item,
                    metadata: ItemMetadata {
                        created_at: 0,
                        modified_at: 0,
                        pinned: false,
                    },
                }],
            }],
            exporter_rp_id: "other-app.example".to_string(),
            exporter_display_name: "Other Password Manager".to_string(),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn full_export_import_self_loop_round_trips() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![CxpCredentialType::BasicAuth],
            })
            .unwrap();

        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap();
        assert!(encrypted_response.warnings.is_empty());

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        assert_eq!(result.vaults.len(), 1);
        let imported_vault = &result.vaults[0];
        assert_eq!(imported_vault.vault.as_ref().unwrap().name, "Personal");
        let imported_item = &imported_vault.items[0];
        let ItemContent::Login(login) = &imported_item.content else {
            panic!("expected login content")
        };
        assert_eq!(login.email, "alice@example.com");
        assert_eq!(login.password, "hunter2");
    }

    #[test]
    fn processing_a_response_without_a_pending_request_returns_invalid_state() {
        let importer = CxpImportHandler::new();
        let result = importer.process_export_response(b"anything");
        assert!(matches!(result, Err(CxpError::InvalidState(_))));
    }

    #[test]
    fn processing_a_response_twice_returns_invalid_state_on_the_second_call() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap()
            .response;

        assert!(importer.process_export_response(&encrypted_response).is_ok());
        assert!(matches!(
            importer.process_export_response(&encrypted_response),
            Err(CxpError::InvalidState(_))
        ));
    }

    #[test]
    fn starting_a_new_request_discards_a_not_yet_completed_one() {
        let importer = CxpImportHandler::new();

        let stale_request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "First".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        importer
            .create_export_request(CxpExportRequest {
                importer_name: "Second".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        // Encrypted for the discarded "First" request's ephemeral key; the handler is now holding
        // "Second"'s key material instead, so decryption must fail rather than silently succeed.
        let exporter = CxpExportHandler::new();
        let response = exporter
            .create_export_response(&stale_request, sample_export_input())
            .unwrap()
            .response;

        let result = importer.process_export_response(&response);
        assert!(matches!(result, Err(CxpError::DecryptionError(_))));
    }

    #[test]
    fn unsupported_hpke_parameters_from_peer_are_rejected_cleanly() {
        let request = r#"{
            "version": 0,
            "hpke": [{
                "mode": "base",
                "kem": 16,
                "kdf": 1,
                "aead": 2,
                "key": null
            }],
            "importer": "Some Importer"
        }"#;

        let exporter = CxpExportHandler::new();
        let result = exporter.create_export_response(request, sample_export_input());
        assert!(matches!(result, Err(CxpError::UnsupportedHpkeParameters(_))));
    }

    #[test]
    fn malformed_export_request_returns_clean_error() {
        let exporter = CxpExportHandler::new();
        let result = exporter.create_export_response("not json", sample_export_input());
        assert!(matches!(result, Err(CxpError::DeserializationError(_))));
    }

    #[test]
    fn parse_export_request_summarizes_importer_and_credential_types() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![CxpCredentialType::BasicAuth, CxpCredentialType::Passkey],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let summary = exporter.parse_export_request(&request).unwrap();

        assert_eq!(summary.importer_name, "Proton Pass");
        assert_eq!(
            summary.requested_credential_types,
            vec![CxpCredentialType::BasicAuth, CxpCredentialType::Passkey]
        );
        assert!(!summary.requests_all_credential_types);
    }

    #[test]
    fn parse_export_request_reports_no_restriction_when_credential_types_absent() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let summary = exporter.parse_export_request(&request).unwrap();

        assert!(summary.requested_credential_types.is_empty());
        assert!(summary.requests_all_credential_types);
    }

    #[test]
    fn parse_export_request_drops_unrecognized_credential_types() {
        let request = r#"{
            "version": 0,
            "hpke": [],
            "importer": "Some Importer",
            "credentialTypes": ["basic-auth", "some-future-type"]
        }"#;

        let exporter = CxpExportHandler::new();
        let summary = exporter.parse_export_request(request).unwrap();

        assert_eq!(summary.importer_name, "Some Importer");
        assert_eq!(summary.requested_credential_types, vec![CxpCredentialType::BasicAuth]);
        assert!(!summary.requests_all_credential_types);
    }

    #[test]
    fn parse_export_request_returns_clean_error_on_malformed_json() {
        let exporter = CxpExportHandler::new();
        let result = exporter.parse_export_request("not json");
        assert!(matches!(result, Err(CxpError::DeserializationError(_))));
    }

    #[test]
    fn create_export_response_only_includes_requested_credential_types() {
        use proton_pass_types::{CardType, CreditCardItem};

        let login = ItemData::new(
            "My login".to_string(),
            String::new(),
            String::new(),
            ItemContent::Login(LoginItem {
                email: "alice@example.com".to_string(),
                username: String::new(),
                password: "hunter2".to_string(),
                urls: Vec::new(),
                totp_uri: String::new(),
                passkeys: Vec::new(),
                autofill_urls: Vec::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let credit_card = ItemData::new(
            "My card".to_string(),
            String::new(),
            String::new(),
            ItemContent::CreditCard(CreditCardItem {
                cardholder_name: "Alice".to_string(),
                card_type: CardType::Visa,
                number: "4111111111111111".to_string(),
                verification_number: "123".to_string(),
                expiration_date: "2030-01".to_string(),
                pin: String::new(),
            }),
            Vec::new(),
        )
        .unwrap();
        let vault = VaultData::new(
            "Personal".to_string(),
            String::new(),
            VaultDisplayPreferences::default(),
        )
        .unwrap();

        let export = CxfExportInput {
            vaults: vec![CxfVaultWithItems {
                vault,
                items: vec![
                    ItemWithMetadata {
                        item: login,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                    ItemWithMetadata {
                        item: credit_card,
                        metadata: ItemMetadata {
                            created_at: 0,
                            modified_at: 0,
                            pinned: false,
                        },
                    },
                ],
            }],
            exporter_rp_id: "other-app.example".to_string(),
            exporter_display_name: "Other Password Manager".to_string(),
            timestamp: 1_700_000_000,
        };

        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![CxpCredentialType::CreditCard],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let encrypted_response = exporter.create_export_response(&request, export).unwrap();

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        let imported_items = &result.vaults[0].items;
        assert_eq!(imported_items.len(), 1);
        assert!(matches!(imported_items[0].content, ItemContent::CreditCard(_)));
    }

    #[test]
    fn create_export_response_includes_everything_when_request_has_no_restriction() {
        let importer = CxpImportHandler::new();
        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let exporter = CxpExportHandler::new();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap();

        let result = importer.process_export_response(&encrypted_response.response).unwrap();
        assert_eq!(result.vaults[0].items.len(), 1);
    }

    #[test]
    fn complete_export_rejects_a_response_with_an_unsupported_version() {
        let importer = CxpImportHandler::new();
        importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let response = r#"{
            "version": 7,
            "hpke": { "mode": "base", "kem": 32, "kdf": 1, "aead": 3, "key": null },
            "exporter": "Other App",
            "payload": "AAAA"
        }"#;

        let result = importer.process_export_response(response.as_bytes());
        assert!(matches!(result, Err(CxpError::UnsupportedHpkeParameters(_))));
    }

    #[test]
    fn malformed_export_response_returns_clean_error() {
        let importer = CxpImportHandler::new();
        importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();

        let result = importer.process_export_response(b"not json");
        assert!(matches!(result, Err(CxpError::DeserializationError(_))));
    }

    #[test]
    fn truncated_ciphertext_returns_clean_error_not_a_panic() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let mut encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap()
            .response;
        encrypted_response.truncate(encrypted_response.len() / 2);

        let result = importer.process_export_response(&encrypted_response);
        assert!(matches!(
            result,
            Err(CxpError::DeserializationError(_)) | Err(CxpError::DecryptionError(_))
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_authentication_not_a_panic() {
        let importer = CxpImportHandler::new();
        let exporter = CxpExportHandler::new();

        let request = importer
            .create_export_request(CxpExportRequest {
                importer_name: "Proton Pass".to_string(),
                supported_credential_types: vec![],
            })
            .unwrap();
        let encrypted_response = exporter
            .create_export_response(&request, sample_export_input())
            .unwrap()
            .response;
        let mut response: serde_json::Value = serde_json::from_slice(&encrypted_response).unwrap();
        let payload = response["payload"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = payload.chars().collect();
        let flip_index = chars.len() / 2;
        chars[flip_index] = if chars[flip_index] == 'A' { 'B' } else { 'A' };
        response["payload"] = serde_json::Value::String(chars.into_iter().collect());
        let tampered = serde_json::to_vec(&response).unwrap();

        let result = importer.process_export_response(&tampered);
        assert!(matches!(result, Err(CxpError::DecryptionError(_))));
    }
}
