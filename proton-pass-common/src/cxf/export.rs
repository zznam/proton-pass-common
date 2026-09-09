use credential_exchange_format::{CredentialScope, LinkedItem, Version};
use proton_pass_types::{ItemContent, ItemData, ItemExtraFieldContent};

use super::credentials::{credit_card, custom, identity, login, note, passkey, ssh_key, wifi};
use super::vault::{generate_id, generate_item_id, vault_to_collection};
use super::{
    CxfAccount, CxfCredential, CxfError, CxfExportInput, CxfExportResult, CxfHeader, CxfItem, CxfWarning,
    CxfWarningKind, ItemMetadata,
};

struct ItemExport {
    credentials: Vec<CxfCredential>,
    scope: Option<CredentialScope>,
}

fn push_top_level_totps(fields: &[proton_pass_types::ItemExtraField], result: &mut Vec<String>) {
    for field in fields {
        if let ItemExtraFieldContent::Totp(uri) = &field.content {
            result.push(uri.clone());
        }
    }
}

fn collect_extra_totps(item: &ItemData) -> Vec<String> {
    let mut result = Vec::new();

    push_top_level_totps(&item.extra_fields, &mut result);

    let sections: &[proton_pass_types::CustomSection] = match &item.content {
        ItemContent::SshKey(s) => &s.sections,
        ItemContent::Wifi(w) => &w.sections,
        ItemContent::Custom(c) => &c.sections,
        ItemContent::Identity(identity) => &identity.extra_sections,
        _ => &[],
    };
    for section in sections {
        push_top_level_totps(&section.section_fields, &mut result);
    }

    if let ItemContent::Identity(identity) = &item.content {
        push_top_level_totps(&identity.extra_personal_details, &mut result);
        push_top_level_totps(&identity.extra_address_details, &mut result);
        push_top_level_totps(&identity.extra_contact_details, &mut result);
        push_top_level_totps(&identity.extra_work_details, &mut result);
    }

    result
}

fn item_to_export(item: &ItemData, warnings: &mut Vec<CxfWarning>) -> ItemExport {
    let title = Some(item.title.as_str());
    let mut credentials = Vec::new();
    let mut scope = None;

    match &item.content {
        ItemContent::Login(login_item) => {
            credentials.push(login::login_basics_to_credential(login_item));
            if let Some(cred) = login::login_identifiers_credential(login_item) {
                credentials.push(cred);
            }
            if !login_item.totp_uri.is_empty() {
                match login::totp_uri_to_credential(&login_item.totp_uri) {
                    Some(cred) => credentials.push(cred),
                    None => warnings.push(CxfWarning {
                        item_title: title.map(str::to_string),
                        message: "Could not export login TOTP: unsupported or malformed otpauth URI".to_string(),
                        kind: CxfWarningKind::MalformedInput,
                    }),
                }
            }
            for pk in &login_item.passkeys {
                match passkey::passkey_to_credential(pk) {
                    Ok(cred) => credentials.push(cred),
                    Err(e) => warnings.push(CxfWarning {
                        item_title: title.map(str::to_string),
                        message: format!("Could not export passkey: {e}"),
                        kind: CxfWarningKind::MalformedInput,
                    }),
                }
            }
            let urls: Vec<String> = if login_item.autofill_urls.is_empty() {
                login_item.urls.clone()
            } else {
                login_item.autofill_urls.iter().map(|a| a.url.clone()).collect()
            };
            scope = login::urls_to_scope(&urls);
        }
        ItemContent::Note(_) => {}
        ItemContent::Alias(_) => {}
        ItemContent::CreditCard(cc) => credentials.push(credit_card::credit_card_to_credential(cc, title, warnings)),
        ItemContent::SshKey(ssh) => {
            if let Some(cred) = ssh_key::ssh_key_to_credential(ssh, title, warnings) {
                credentials.push(cred);
            }
            if let Some(cred) = ssh_key::public_key_to_credential(&ssh.public_key) {
                credentials.push(cred);
            }
            for section in &ssh.sections {
                credentials.push(custom::custom_section_to_credential(section));
            }
        }
        ItemContent::Wifi(wifi_item) => {
            credentials.push(wifi::wifi_to_credential(wifi_item));
            for section in &wifi_item.sections {
                credentials.push(custom::custom_section_to_credential(section));
            }
        }
        ItemContent::Custom(custom_item) => {
            credentials.extend(custom::custom_item_to_credentials(custom_item));
        }
        ItemContent::Identity(identity_item) => {
            credentials.extend(identity::identity_to_credentials(identity_item, title, warnings));
        }
    }

    for uri in collect_extra_totps(item) {
        match login::totp_uri_to_credential(&uri) {
            Some(cred) => credentials.push(cred),
            None => warnings.push(CxfWarning {
                item_title: title.map(str::to_string),
                message: "Could not export a TOTP field: unsupported or malformed otpauth URI".to_string(),
                kind: CxfWarningKind::MalformedInput,
            }),
        }
    }

    if let Some(cred) = custom::extra_fields_to_credential(&item.extra_fields) {
        credentials.push(cred);
    }

    if !item.note.is_empty() {
        credentials.push(note::note_text_to_credential(&item.note));
    }

    ItemExport { credentials, scope }
}

fn item_data_to_cxf_item(item: &ItemData, metadata: &ItemMetadata, warnings: &mut Vec<CxfWarning>) -> Option<CxfItem> {
    let export = item_to_export(item, warnings);
    if export.credentials.is_empty() {
        warnings.push(CxfWarning {
            item_title: Some(item.title.clone()),
            message: "Item has no credentials to export and will be skipped".to_string(),
            kind: CxfWarningKind::UnsupportedItemType,
        });
        return None;
    }
    Some(CxfItem {
        id: generate_item_id(&item.item_uuid),
        creation_at: Some(metadata.created_at),
        modified_at: Some(metadata.modified_at),
        title: item.title.clone(),
        subtitle: None,
        favorite: metadata.pinned.then_some(true),
        scope: export.scope,
        credentials: export.credentials,
        tags: None,
        extensions: None,
    })
}

pub fn export(input: CxfExportInput) -> Result<CxfExportResult, CxfError> {
    let mut warnings = Vec::new();
    let mut account_items = Vec::new();
    let mut collections = Vec::new();

    for vault_with_items in &input.vaults {
        let mut linked_items = Vec::new();
        for item_with_metadata in &vault_with_items.items {
            if matches!(item_with_metadata.item.content, ItemContent::Alias(_)) {
                continue;
            }
            let Some(cxf_item) =
                item_data_to_cxf_item(&item_with_metadata.item, &item_with_metadata.metadata, &mut warnings)
            else {
                continue;
            };
            linked_items.push(LinkedItem {
                item: cxf_item.id.clone(),
                account: None,
            });
            account_items.push(cxf_item);
        }
        let collection = vault_to_collection(&vault_with_items.vault, generate_id(), linked_items);
        collections.push(collection);
    }

    let account = CxfAccount {
        id: generate_id(),
        username: String::new(),
        email: String::new(),
        full_name: None,
        collections,
        items: account_items,
        extensions: None,
    };

    let header = CxfHeader {
        version: Version { major: 1, minor: 0 },
        exporter_rp_id: input.exporter_rp_id,
        exporter_display_name: input.exporter_display_name,
        timestamp: input.timestamp,
        accounts: vec![account],
    };

    let payload = serde_json::to_string(&header).map_err(|e| CxfError::SerializationError(e.to_string()))?;

    Ok(CxfExportResult { payload, warnings })
}
