use credential_exchange_format::{
    B64Url, Credential, CustomFieldsCredential, EditableFieldValue, Header, Item, TotpCredential,
};
use proton_pass_types::{
    CustomSection, ItemContent, ItemData, ItemExtraField, ItemExtraFieldContent, LoginItem, NoteItem, VaultData,
};
use std::collections::{HashMap, HashSet};

use super::credentials::{credit_card, custom, identity, login, note, passkey, ssh_key, wifi};
use super::vault::collection_to_vault;
use super::{
    CxfCredential, CxfError, CxfImportResult, CxfImportedVault, CxfItem, CxfWarning, CxfWarningKind, ProtonExtension,
};

enum Primary {
    Login,
    SshKey,
    Wifi,
    CreditCard,
    Identity,
    Note,
    Custom,
    None,
}

fn pick_primary(credentials: &[CxfCredential]) -> Primary {
    let has = |f: &dyn Fn(&CxfCredential) -> bool| credentials.iter().any(f);

    if has(&|c| matches!(c, Credential::Passkey(_))) {
        return Primary::Login;
    }
    if has(&|c| matches!(c, Credential::BasicAuth(_))) || has(&|c| matches!(c, Credential::GeneratedPassword(_))) {
        return Primary::Login;
    }
    if has(&|c| matches!(c, Credential::SshKey(_))) {
        return Primary::SshKey;
    }
    if has(&|c| matches!(c, Credential::Wifi(_))) {
        return Primary::Wifi;
    }
    if has(&|c| matches!(c, Credential::CreditCard(_))) {
        return Primary::CreditCard;
    }
    if has(&|c| {
        matches!(
            c,
            Credential::Address(_)
                | Credential::DriversLicense(_)
                | Credential::IdentityDocument(_)
                | Credential::Passport(_)
                | Credential::PersonName(_)
        )
    }) {
        return Primary::Identity;
    }
    if has(&|c| matches!(c, Credential::Note(_))) {
        return Primary::Note;
    }
    if has(&|c| matches!(c, Credential::CustomFields(_))) {
        return Primary::Custom;
    }
    Primary::None
}

struct TotpSplit<'a> {
    primary: Option<&'a TotpCredential>,
    extra: Vec<&'a TotpCredential>,
}

/// CXF has no concept of a "primary" TOTP, so by convention the first `totp` credential is treated
/// as the item's primary one and the rest are extra.
fn split_totps(item: &CxfItem, wants_primary: bool) -> TotpSplit<'_> {
    let mut totps = item.credentials.iter().filter_map(|c| match c {
        Credential::Totp(t) => Some(t.as_ref()),
        _ => None,
    });

    let primary = wants_primary.then(|| totps.next()).flatten();
    let extra = totps.collect();

    TotpSplit { primary, extra }
}

fn apply_extra_totps(
    item_title: &str,
    extra: Vec<&TotpCredential>,
    extra_fields: &mut Vec<ItemExtraField>,
    warnings: &mut Vec<CxfWarning>,
) {
    for (i, totp) in extra.into_iter().enumerate() {
        let uri = login::credential_to_totp_uri(totp, Some(item_title), warnings);
        let name = if i == 0 {
            "TOTP".to_string()
        } else {
            format!("TOTP {}", i + 1)
        };
        extra_fields.push(ItemExtraField {
            name,
            content: ItemExtraFieldContent::Totp(uri),
        });
    }
}

fn credential_to_custom_fields_extras(
    cred: &CustomFieldsCredential<ProtonExtension>,
    item_title: &str,
    warnings: &mut Vec<CxfWarning>,
) -> (Vec<ItemExtraField>, Option<CustomSection>) {
    if cred.label.is_some() {
        let section = custom::credential_to_custom_section(cred, Some(item_title), warnings);
        (Vec::new(), Some(section))
    } else {
        let fields = cred
            .fields
            .iter()
            .map(|f| custom::editable_value_to_extra_field(f, Some(item_title), warnings))
            .collect();
        (fields, None)
    }
}

fn item_to_data(item: &CxfItem, warnings: &mut Vec<CxfWarning>) -> ItemData {
    let title = if item.title.is_empty() {
        "Untitled".to_string()
    } else {
        item.title.clone()
    };
    let primary = pick_primary(&item.credentials);
    let wants_login_totp = matches!(primary, Primary::Login);

    let mut extra_fields: Vec<ItemExtraField> = Vec::new();
    let mut note_text = String::new();
    let mut public_key = String::new();
    let mut extra_sections: Vec<CustomSection> = Vec::new();

    let mut content = match primary {
        Primary::Login => {
            let mut login_item = item
                .credentials
                .iter()
                .find_map(|c| match c {
                    Credential::BasicAuth(cred) => Some(login::credential_to_login_basics(cred)),
                    _ => None,
                })
                .or_else(|| {
                    item.credentials.iter().find_map(|c| match c {
                        Credential::GeneratedPassword(cred) => Some(login::generated_password_to_login(cred)),
                        _ => None,
                    })
                })
                .unwrap_or_else(|| LoginItem {
                    email: String::new(),
                    username: String::new(),
                    password: String::new(),
                    urls: Vec::new(),
                    totp_uri: String::new(),
                    passkeys: Vec::new(),
                    autofill_urls: Vec::new(),
                });

            let (identifier_email, identifier_username) = login::extract_login_identifiers(&item.credentials);
            if identifier_email.is_some() || identifier_username.is_some() {
                login_item.email = identifier_email.unwrap_or_default();
                login_item.username = identifier_username.unwrap_or_default();
            }

            for cred in &item.credentials {
                if let Credential::Passkey(pk) = cred {
                    match passkey::credential_to_passkey(pk) {
                        Ok(passkey) => login_item.passkeys.push(passkey),
                        Err(e) => warnings.push(CxfWarning {
                            item_title: Some(title.clone()),
                            message: format!("Could not import passkey: {e}"),
                            kind: CxfWarningKind::MalformedInput,
                        }),
                    }
                }
            }

            if let Some(scope) = &item.scope {
                login_item.autofill_urls = login::scope_to_autofill_urls(Some(scope));
                login_item.urls = scope.urls.clone();
            }

            let split = split_totps(item, wants_login_totp);
            if let Some(primary_totp) = split.primary {
                login_item.totp_uri = login::credential_to_totp_uri(primary_totp, Some(&title), warnings);
            }
            apply_extra_totps(&title, split.extra, &mut extra_fields, warnings);

            ItemContent::Login(login_item)
        }
        Primary::SshKey => {
            let ssh_item = item.credentials.iter().find_map(|c| match c {
                Credential::SshKey(cred) => Some(ssh_key::credential_to_ssh_key(
                    cred,
                    String::new(),
                    Some(&title),
                    warnings,
                )),
                _ => None,
            });

            match ssh_item {
                Some(mut ssh_item) => {
                    for cred in &item.credentials {
                        if let Credential::CustomFields(cf) = cred
                            && let Some(pk) = ssh_key::extract_public_key(cf)
                        {
                            public_key = pk;
                        }
                    }
                    ssh_item.public_key = public_key.clone();

                    let split = split_totps(item, false);
                    apply_extra_totps(&title, split.extra, &mut extra_fields, warnings);

                    ItemContent::SshKey(ssh_item)
                }
                None => {
                    warnings.push(CxfWarning {
                        item_title: Some(title.clone()),
                        message: "Expected SshKey credential was not found; imported as an empty note".to_string(),
                        kind: CxfWarningKind::MalformedInput,
                    });
                    ItemContent::Note(NoteItem)
                }
            }
        }
        Primary::Wifi => {
            let wifi_item = item.credentials.iter().find_map(|c| match c {
                Credential::Wifi(cred) => Some(wifi::credential_to_wifi(cred)),
                _ => None,
            });

            match wifi_item {
                Some(wifi_item) => {
                    let split = split_totps(item, false);
                    apply_extra_totps(&title, split.extra, &mut extra_fields, warnings);

                    ItemContent::Wifi(wifi_item)
                }
                None => {
                    warnings.push(CxfWarning {
                        item_title: Some(title.clone()),
                        message: "Expected Wifi credential was not found; imported as an empty note".to_string(),
                        kind: CxfWarningKind::MalformedInput,
                    });
                    ItemContent::Note(NoteItem)
                }
            }
        }
        Primary::CreditCard => {
            let cc_item = item.credentials.iter().find_map(|c| match c {
                Credential::CreditCard(cred) => Some(credit_card::credential_to_credit_card(cred)),
                _ => None,
            });

            match cc_item {
                Some(cc_item) => {
                    let split = split_totps(item, false);
                    apply_extra_totps(&title, split.extra, &mut extra_fields, warnings);

                    ItemContent::CreditCard(cc_item)
                }
                None => {
                    warnings.push(CxfWarning {
                        item_title: Some(title.clone()),
                        message: "Expected CreditCard credential was not found; imported as an empty note".to_string(),
                        kind: CxfWarningKind::MalformedInput,
                    });
                    ItemContent::Note(NoteItem)
                }
            }
        }
        Primary::Identity => {
            let identity_item = identity::credentials_to_identity(&item.credentials, Some(&title), warnings);

            let split = split_totps(item, false);
            apply_extra_totps(&title, split.extra, &mut extra_fields, warnings);

            ItemContent::Identity(Box::new(identity_item))
        }
        Primary::Note => {
            let split = split_totps(item, false);
            apply_extra_totps(&title, split.extra, &mut extra_fields, warnings);
            ItemContent::Note(NoteItem)
        }
        Primary::Custom => {
            let custom_fields: Vec<_> = item
                .credentials
                .iter()
                .filter_map(|cred| match cred {
                    Credential::CustomFields(cf) => Some(cf.as_ref().clone()),
                    _ => None,
                })
                .collect();
            let custom_item = custom::credentials_to_custom_item(&custom_fields, Some(&title), warnings);

            let split = split_totps(item, false);
            apply_extra_totps(&title, split.extra, &mut extra_fields, warnings);

            ItemContent::Custom(custom_item)
        }
        Primary::None => {
            warnings.push(CxfWarning {
                item_title: Some(title.clone()),
                message: "No supported credential found on this item; imported as an empty note".to_string(),
                kind: CxfWarningKind::UnsupportedCredential,
            });
            ItemContent::Note(NoteItem)
        }
    };

    for cred in &item.credentials {
        match cred {
            Credential::Note(cred) => {
                let text = note::credential_to_note_text(cred);
                if note_text.is_empty() {
                    note_text = text;
                }
            }
            Credential::CustomFields(cf) if matches!(primary, Primary::SshKey) && cf.label.is_none() => {
                let fields: Vec<ItemExtraField> = cf
                    .fields
                    .iter()
                    .filter(|f| {
                        !matches!(f, EditableFieldValue::String(s) if s.label.as_deref() == Some(ssh_key::PUBLIC_KEY_FIELD_LABEL))
                    })
                    .map(|f| custom::editable_value_to_extra_field(f, Some(&title), warnings))
                    .collect();
                extra_fields.extend(fields);
            }
            Credential::CustomFields(cf) if matches!(primary, Primary::Login) && cf.label.is_none() => {
                let fields: Vec<ItemExtraField> = cf
                    .fields
                    .iter()
                    .filter(|f| {
                        !matches!(f, EditableFieldValue::String(s) if matches!(s.label.as_deref(), Some(login::EMAIL_FIELD_LABEL) | Some(login::USERNAME_FIELD_LABEL)))
                    })
                    .map(|f| custom::editable_value_to_extra_field(f, Some(&title), warnings))
                    .collect();
                extra_fields.extend(fields);
            }
            Credential::CustomFields(cf) if !matches!(primary, Primary::Custom | Primary::Identity) => {
                let (fields, section) = credential_to_custom_fields_extras(cf, &title, warnings);
                extra_fields.extend(fields);
                if let Some(section) = section {
                    extra_sections.push(section);
                }
            }
            Credential::File(_) | Credential::ItemReference(_) | Credential::ApiKey(_) => {
                warnings.push(CxfWarning {
                    item_title: Some(title.clone()),
                    message: "Unsupported credential type was dropped".to_string(),
                    kind: CxfWarningKind::UnsupportedCredential,
                });
            }
            _ => {}
        }
    }

    match &mut content {
        ItemContent::Identity(identity) => identity.extra_sections.extend(extra_sections),
        ItemContent::SshKey(ssh) => ssh.sections.extend(extra_sections),
        ItemContent::Wifi(wifi_item) => wifi_item.sections.extend(extra_sections),
        ItemContent::Custom(custom_item) => custom_item.sections.extend(extra_sections),
        _ => {
            for section in extra_sections {
                extra_fields.extend(section.section_fields);
            }
        }
    }

    ItemData {
        title,
        note: note_text,
        item_uuid: String::new(),
        content,
        extra_fields,
        platform_specific: None,
        custom_icon: None,
    }
}

pub fn import(payload: &str) -> Result<CxfImportResult, CxfError> {
    let header: Header<ProtonExtension> =
        serde_json::from_str(payload).map_err(|e| CxfError::DeserializationError(e.to_string()))?;

    let mut warnings = Vec::new();
    let mut vaults = Vec::new();

    for account in &header.accounts {
        let mut collected_item_ids = HashSet::new();
        let items_by_id: HashMap<B64Url, &Item<ProtonExtension>> =
            account.items.iter().map(|item| (item.id.clone(), item)).collect();

        for collection in &account.collections {
            let vault: VaultData = collection_to_vault(collection);
            let mut items = Vec::new();
            for linked in &collection.items {
                if let Some(item) = items_by_id.get(&linked.item) {
                    collected_item_ids.insert(item.id.clone());
                    items.push(item_to_data(item, &mut warnings));
                }
            }
            vaults.push(CxfImportedVault {
                vault: Some(vault),
                items,
            });
        }

        let uncollected: Vec<ItemData> = account
            .items
            .iter()
            .filter(|item| !collected_item_ids.contains(&item.id))
            .map(|item| item_to_data(item, &mut warnings))
            .collect();
        if !uncollected.is_empty() {
            vaults.push(CxfImportedVault {
                vault: None,
                items: uncollected,
            });
        }
    }

    Ok(CxfImportResult { vaults, warnings })
}
