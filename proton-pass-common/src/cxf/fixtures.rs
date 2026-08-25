use credential_exchange_format::Header;
use proton_pass_types::{CardType, ItemContent, ItemExtraFieldContent, WifiSecurity};

use super::{
    CxfExportInput, CxfVaultWithItems, ItemMetadata, ItemWithMetadata, ProtonExtension, export_cxf, import_cxf,
};

fn default_metadata() -> ItemMetadata {
    ItemMetadata {
        created_at: 0,
        modified_at: 0,
        pinned: false,
    }
}

fn parse_with_crate(payload: &str) {
    serde_json::from_str::<Header<ProtonExtension>>(payload).expect("fixture must be spec-valid CXF JSON");
}

fn assert_round_trips(payload: &str) {
    let imported = import_cxf(payload).unwrap();
    assert!(imported.warnings.is_empty(), "{:?}", imported.warnings);

    let vaults: Vec<CxfVaultWithItems> = imported
        .vaults
        .into_iter()
        .map(|v| CxfVaultWithItems {
            vault: v.vault.unwrap_or_else(|| {
                proton_pass_types::VaultData::new(
                    "Imported Items".to_string(),
                    String::new(),
                    proton_pass_types::VaultDisplayPreferences::default(),
                )
                .unwrap()
            }),
            items: v
                .items
                .into_iter()
                .map(|item| ItemWithMetadata {
                    item,
                    metadata: default_metadata(),
                })
                .collect(),
        })
        .collect();
    let expected_items: Vec<_> = vaults
        .iter()
        .flat_map(|v| v.items.iter().map(|i| i.item.clone()))
        .collect();

    let re_exported = export_cxf(CxfExportInput {
        vaults,
        exporter_rp_id: "example.com".to_string(),
        exporter_display_name: "Example Exporter".to_string(),
        timestamp: 1700000000,
    })
    .unwrap();
    assert!(re_exported.warnings.is_empty(), "{:?}", re_exported.warnings);

    let re_imported = import_cxf(&re_exported.payload).unwrap();
    assert!(re_imported.warnings.is_empty(), "{:?}", re_imported.warnings);
    let actual_items: Vec<_> = re_imported.vaults.into_iter().flat_map(|v| v.items).collect();
    assert_eq!(
        actual_items, expected_items,
        "second export/import round-trip lost data"
    );
}

#[test]
fn login_totp_scope_fixture_imports_correctly() {
    let payload = include_str!("../../test_data/cxf/login_totp_scope.json");
    parse_with_crate(payload);
    assert_round_trips(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(result.vaults.len(), 1);
    let vault = &result.vaults[0];
    assert_eq!(vault.vault.as_ref().unwrap().name, "Personal");
    assert_eq!(vault.items.len(), 1);

    let item = &vault.items[0];
    assert_eq!(item.title, "My Login");
    let ItemContent::Login(login) = &item.content else {
        panic!("expected login content")
    };
    assert_eq!(login.email, "alice@example.com");
    assert_eq!(login.password, "hunter2");
    assert!(login.totp_uri.contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(login.autofill_urls.len(), 1);
    assert_eq!(login.autofill_urls[0].url, "https://example.com");
}

#[test]
fn login_passkey_totp_scope_fixture_imports_correctly() {
    let payload = include_str!("../../test_data/cxf/login_passkey_totp_scope.json");
    parse_with_crate(payload);
    assert_round_trips(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let item = &result.vaults[0].items[0];
    let ItemContent::Login(login) = &item.content else {
        panic!("expected login content")
    };
    assert_eq!(login.email, "jane@example.com");
    assert_eq!(login.password, "hunter2");
    assert!(login.totp_uri.contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(login.autofill_urls.len(), 1);
    assert_eq!(login.passkeys.len(), 1);
    assert_eq!(login.passkeys[0].rp_id, "example.com");
    assert_eq!(login.passkeys[0].credential_id, vec![1, 2, 3, 4]);
    assert_eq!(login.passkeys[0].user_handle, vec![5, 6, 7, 8]);
    assert_eq!(login.passkeys[0].user_display_name, "Jane Doe");
}

#[test]
fn identity_full_fixture_imports_correctly() {
    let payload = include_str!("../../test_data/cxf/identity_full.json");
    parse_with_crate(payload);
    assert_round_trips(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let item = &result.vaults[0].items[0];
    let ItemContent::Identity(identity) = &item.content else {
        panic!("expected identity content")
    };
    assert_eq!(identity.first_name, "Jane");
    assert_eq!(identity.middle_name, "Q");
    assert_eq!(identity.last_name, "Doe");
    assert_eq!(identity.street_address, "1 Main St");
    assert_eq!(identity.zip_or_postal_code, "12345");
    assert_eq!(identity.city, "Springfield");
    assert_eq!(identity.state_or_province, "CA");
    assert_eq!(identity.country_or_region, "US");
    assert_eq!(identity.phone_number, "555-1234");
    assert_eq!(identity.license_number, "D7654321");
    assert_eq!(identity.passport_number, "P1234567");
    assert_eq!(identity.social_security_number, "123-45-6789");
    assert_eq!(identity.organization, "Acme Corp");
    assert_eq!(identity.email, "jane@example.com");
}

#[test]
fn credit_card_fixture_imports_correctly() {
    let payload = include_str!("../../test_data/cxf/credit_card.json");
    parse_with_crate(payload);
    assert_round_trips(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let item = &result.vaults[0].items[0];
    let ItemContent::CreditCard(cc) = &item.content else {
        panic!("expected credit card content")
    };
    assert_eq!(cc.cardholder_name, "John Doe");
    assert_eq!(cc.number, "4111111111111111");
    assert_eq!(cc.card_type, CardType::Visa);
    assert_eq!(cc.verification_number, "123");
    assert_eq!(cc.expiration_date, "2030-05");
}

#[test]
fn ssh_key_fixture_imports_correctly() {
    let payload = include_str!("../../test_data/cxf/ssh_key.json");
    parse_with_crate(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let item = &result.vaults[0].items[0];
    let ItemContent::SshKey(ssh) = &item.content else {
        panic!("expected ssh key content")
    };
    assert_eq!(ssh.public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5");
    assert!(!ssh.private_key.is_empty());
}

#[test]
fn wifi_fixture_imports_correctly() {
    let payload = include_str!("../../test_data/cxf/wifi.json");
    parse_with_crate(payload);
    assert_round_trips(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let item = &result.vaults[0].items[0];
    let ItemContent::Wifi(wifi) = &item.content else {
        panic!("expected wifi content")
    };
    assert_eq!(wifi.ssid, "MyNetwork");
    assert_eq!(wifi.password, "hunter2");
    assert_eq!(wifi.security, WifiSecurity::WPA2);
}

#[test]
fn custom_item_with_totp_fixture_imports_correctly() {
    let payload = include_str!("../../test_data/cxf/custom_item_with_totp.json");
    parse_with_crate(payload);
    assert_round_trips(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let item = &result.vaults[0].items[0];
    let ItemContent::Custom(custom) = &item.content else {
        panic!("expected custom content")
    };
    let section = custom
        .sections
        .iter()
        .find(|s| s.section_name == "Section A")
        .expect("section preserved");
    assert!(section.section_fields.iter().any(|f| f.name == "field1"));
    let totp_field = item
        .extra_fields
        .iter()
        .find(|f| f.name == "TOTP")
        .expect("extra totp credential imported as a generic top-level extra field");
    match &totp_field.content {
        ItemExtraFieldContent::Totp(uri) => assert!(uri.contains("MFRGGZDFMZTWQ2LK")),
        other => panic!("expected totp content, got {other:?}"),
    }
}

#[test]
fn multi_vault_fixture_imports_into_separate_vaults() {
    let payload = include_str!("../../test_data/cxf/multi_vault.json");
    parse_with_crate(payload);
    assert_round_trips(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(result.vaults.len(), 2);
    let names: Vec<String> = result
        .vaults
        .iter()
        .map(|v| v.vault.as_ref().unwrap().name.clone())
        .collect();
    assert!(names.contains(&"Vault One".to_string()));
    assert!(names.contains(&"Vault Two".to_string()));
}

#[test]
fn foreign_lossy_fixture_falls_back_to_generic_totp_naming() {
    let payload = include_str!("../../test_data/cxf/foreign_lossy.json");
    parse_with_crate(payload);

    let result = import_cxf(payload).unwrap();
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);

    let item = &result.vaults[0].items[0];
    let ItemContent::Login(login) = &item.content else {
        panic!("expected login content")
    };
    assert!(login.totp_uri.contains("JBSWY3DPEHPK3PXP"));
    let fallback_field = item
        .extra_fields
        .iter()
        .find(|f| f.name == "TOTP")
        .expect("second totp preserved under generic fallback name");
    match &fallback_field.content {
        ItemExtraFieldContent::Totp(uri) => assert!(uri.contains("GEZDGNBVGY3TQOJQ")),
        other => panic!("expected totp content, got {other:?}"),
    }
}
