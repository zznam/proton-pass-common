#![cfg(feature = "cxf")]

use std::fs;

use proton_pass_common::cxf::{
    CxfExportInput, CxfImportResult, CxfVaultWithItems, ItemMetadata, ItemWithMetadata, export_cxf, import_cxf,
};
use proton_pass_common::passkey::{PasskeyResult, WebauthnFetcher, generate_passkey_for_domain};
use proton_pass_types::{
    AliasItem, AutofillUrl, AutofillUrlMode, CardType, CreditCardItem, CustomItem, CustomSection, IdentityItem,
    ItemContent, ItemData, ItemExtraField, ItemExtraFieldContent, LoginItem, NoteItem, Passkey, SshKeyItem, VaultData,
    VaultDisplayPreferences, WifiItem, WifiSecurity,
};

const BASELINE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/cxf/full_library_baseline.json");

const EXPORTER_RP_ID: &str = "proton.me";
const EXPORTER_DISPLAY_NAME: &str = "Proton Pass";
const EXPORT_TIMESTAMP: u64 = 1_700_000_000;

const VAULT_PERSONAL: &str = "Personal";
const VAULT_WORK: &str = "Work";

const LOGIN_TITLE: &str = "My Login";
const LOGIN_EMAIL: &str = "alice@example.com";
const LOGIN_PASSWORD: &str = "hunter2";
const LOGIN_URL: &str = "https://example.com";
const LOGIN_TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

const PASSKEY_DOMAIN: &str = "https://example.com";
const PASSKEY_RP_ID: &str = "example.com";
const PASSKEY_1_USER_ID_B64: &str = "YWxpY2UtdXNlci1pZC0x";
const PASSKEY_1_USER_NAME: &str = "alice";
const PASSKEY_1_USER_DISPLAY_NAME: &str = "Alice Example";
const PASSKEY_2_USER_ID_B64: &str = "YWxpY2UtdXNlci1pZC0y";
const PASSKEY_2_USER_NAME: &str = "alice-backup";
const PASSKEY_2_USER_DISPLAY_NAME: &str = "Alice Backup";
const PASSKEY_CHALLENGE_B64: &str = "YS1maXhlZC1jaGFsbGVuZ2UtdmFsdWU";

const NOTE_TITLE: &str = "My Note";
const NOTE_CONTENT: &str = "Remember the milk";

const CREDIT_CARD_TITLE: &str = "My Card";
const CREDIT_CARD_HOLDER: &str = "Alice Example";
const CREDIT_CARD_NUMBER: &str = "4111111111111111";
const CREDIT_CARD_CVV: &str = "123";
const CREDIT_CARD_EXPIRATION: &str = "2030-05";
const CREDIT_CARD_PIN: &str = "1234";

const IDENTITY_TITLE: &str = "My Identity";
const IDENTITY_FIRST_NAME: &str = "Alice";
const IDENTITY_LAST_NAME: &str = "Example";
const IDENTITY_EMAIL: &str = "identity@example.com";
const IDENTITY_STREET_ADDRESS: &str = "1 Main St";
const IDENTITY_CITY: &str = "Springfield";

const SSH_KEY_TITLE: &str = "My SSH Key";
const SSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder\n-----END OPENSSH PRIVATE KEY-----";
const SSH_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test-key";

const WIFI_TITLE: &str = "My WiFi";
const WIFI_SSID: &str = "MyNetwork";
const WIFI_PASSWORD: &str = "wifi-password";

const CUSTOM_TITLE: &str = "My Custom Item";
const CUSTOM_SECTION_NAME: &str = "Section A";
const CUSTOM_FIELD_NAME: &str = "field1";
const CUSTOM_FIELD_VALUE: &str = "value1";

const ALIAS_TITLE: &str = "My Alias";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

fn create_passkey(
    rt: &tokio::runtime::Runtime,
    user_id_b64: &str,
    user_name: &str,
    user_display_name: &str,
) -> Passkey {
    let request = format!(
        r#"{{
            "rp": {{"id": "{PASSKEY_RP_ID}", "name": "Example"}},
            "user": {{"id": "{user_id_b64}", "name": "{user_name}", "displayName": "{user_display_name}"}},
            "pubKeyCredParams": [{{"type": "public-key", "alg": -7}}],
            "authenticatorSelection": {{"residentKey": "required"}},
            "timeout": 60000,
            "challenge": "{PASSKEY_CHALLENGE_B64}"
        }}"#
    );

    let response: PasskeyResult<_> = rt.block_on(async {
        generate_passkey_for_domain(PASSKEY_DOMAIN, &request, false, WebauthnFetcher::new(None)).await
    });
    let response = response.expect("passkey generation should succeed");

    Passkey {
        key_id: response.key_id,
        content: response.passkey,
        domain: response.domain,
        rp_id: response.rp_id.unwrap_or_default(),
        rp_name: response.rp_name,
        user_name: response.user_name,
        user_display_name: response.user_display_name,
        user_id: response.user_id,
        create_time: 0,
        note: String::new(),
        credential_id: response.credential_id,
        user_handle: response.user_handle.unwrap_or_default(),
        creation_data: None,
    }
}

fn login_item(rt: &tokio::runtime::Runtime) -> ItemData {
    let passkey1 = create_passkey(
        rt,
        PASSKEY_1_USER_ID_B64,
        PASSKEY_1_USER_NAME,
        PASSKEY_1_USER_DISPLAY_NAME,
    );
    let passkey2 = create_passkey(
        rt,
        PASSKEY_2_USER_ID_B64,
        PASSKEY_2_USER_NAME,
        PASSKEY_2_USER_DISPLAY_NAME,
    );

    let login = LoginItem {
        email: LOGIN_EMAIL.to_string(),
        username: String::new(),
        password: LOGIN_PASSWORD.to_string(),
        urls: vec![LOGIN_URL.to_string()],
        totp_uri: format!(
            "otpauth://totp/alice?secret={LOGIN_TOTP_SECRET}&issuer=Proton&algorithm=SHA1&digits=6&period=30"
        ),
        passkeys: vec![passkey1, passkey2],
        autofill_urls: vec![AutofillUrl {
            url: LOGIN_URL.to_string(),
            mode: AutofillUrlMode::Default,
        }],
    };
    ItemData::new(
        LOGIN_TITLE.to_string(),
        String::new(),
        String::new(),
        ItemContent::Login(login),
        Vec::new(),
    )
    .unwrap()
}

fn note_item() -> ItemData {
    ItemData::new(
        NOTE_TITLE.to_string(),
        NOTE_CONTENT.to_string(),
        String::new(),
        ItemContent::Note(NoteItem),
        Vec::new(),
    )
    .unwrap()
}

fn credit_card_item() -> ItemData {
    let credit_card = CreditCardItem {
        cardholder_name: CREDIT_CARD_HOLDER.to_string(),
        card_type: CardType::Visa,
        number: CREDIT_CARD_NUMBER.to_string(),
        verification_number: CREDIT_CARD_CVV.to_string(),
        expiration_date: CREDIT_CARD_EXPIRATION.to_string(),
        pin: CREDIT_CARD_PIN.to_string(),
    };
    ItemData::new(
        CREDIT_CARD_TITLE.to_string(),
        String::new(),
        String::new(),
        ItemContent::CreditCard(credit_card),
        Vec::new(),
    )
    .unwrap()
}

fn identity_item() -> ItemData {
    let identity = IdentityItem {
        full_name: format!("{IDENTITY_FIRST_NAME} {IDENTITY_LAST_NAME}"),
        email: IDENTITY_EMAIL.to_string(),
        phone_number: String::new(),
        first_name: IDENTITY_FIRST_NAME.to_string(),
        middle_name: String::new(),
        last_name: IDENTITY_LAST_NAME.to_string(),
        birthdate: String::new(),
        gender: String::new(),
        extra_personal_details: Vec::new(),
        organization: String::new(),
        street_address: IDENTITY_STREET_ADDRESS.to_string(),
        zip_or_postal_code: String::new(),
        city: IDENTITY_CITY.to_string(),
        state_or_province: String::new(),
        country_or_region: String::new(),
        floor: String::new(),
        county: String::new(),
        extra_address_details: Vec::new(),
        social_security_number: String::new(),
        passport_number: String::new(),
        license_number: String::new(),
        website: String::new(),
        x_handle: String::new(),
        second_phone_number: String::new(),
        linkedin: String::new(),
        reddit: String::new(),
        facebook: String::new(),
        yahoo: String::new(),
        instagram: String::new(),
        extra_contact_details: Vec::new(),
        company: String::new(),
        job_title: String::new(),
        personal_website: String::new(),
        work_phone_number: String::new(),
        work_email: String::new(),
        extra_work_details: Vec::new(),
        extra_sections: Vec::new(),
    };
    ItemData::new(
        IDENTITY_TITLE.to_string(),
        String::new(),
        String::new(),
        ItemContent::Identity(Box::new(identity)),
        Vec::new(),
    )
    .unwrap()
}

fn ssh_key_item() -> ItemData {
    let ssh_key = SshKeyItem {
        private_key: SSH_PRIVATE_KEY.to_string(),
        public_key: SSH_PUBLIC_KEY.to_string(),
        sections: Vec::new(),
    };
    ItemData::new(
        SSH_KEY_TITLE.to_string(),
        String::new(),
        String::new(),
        ItemContent::SshKey(ssh_key),
        Vec::new(),
    )
    .unwrap()
}

fn wifi_item() -> ItemData {
    let wifi = WifiItem {
        ssid: WIFI_SSID.to_string(),
        password: WIFI_PASSWORD.to_string(),
        security: WifiSecurity::WPA2,
        sections: Vec::new(),
    };
    ItemData::new(
        WIFI_TITLE.to_string(),
        String::new(),
        String::new(),
        ItemContent::Wifi(wifi),
        Vec::new(),
    )
    .unwrap()
}

fn custom_item() -> ItemData {
    let custom = CustomItem {
        sections: vec![CustomSection {
            section_name: CUSTOM_SECTION_NAME.to_string(),
            section_fields: vec![ItemExtraField {
                name: CUSTOM_FIELD_NAME.to_string(),
                content: ItemExtraFieldContent::Text(CUSTOM_FIELD_VALUE.to_string()),
            }],
        }],
    };
    ItemData::new(
        CUSTOM_TITLE.to_string(),
        String::new(),
        String::new(),
        ItemContent::Custom(custom),
        Vec::new(),
    )
    .unwrap()
}

fn alias_item() -> ItemData {
    ItemData::new(
        ALIAS_TITLE.to_string(),
        String::new(),
        String::new(),
        ItemContent::Alias(AliasItem),
        Vec::new(),
    )
    .unwrap()
}

fn vault_data(name: &str) -> VaultData {
    VaultData::new(name.to_string(), String::new(), VaultDisplayPreferences::default()).unwrap()
}

fn with_metadata(item: ItemData) -> ItemWithMetadata {
    ItemWithMetadata {
        item,
        metadata: ItemMetadata {
            created_at: 0,
            modified_at: 0,
            pinned: false,
        },
    }
}

fn build_export_input(rt: &tokio::runtime::Runtime) -> CxfExportInput {
    CxfExportInput {
        vaults: vec![
            CxfVaultWithItems {
                vault: vault_data(VAULT_PERSONAL),
                items: vec![
                    with_metadata(login_item(rt)),
                    with_metadata(note_item()),
                    with_metadata(credit_card_item()),
                    with_metadata(identity_item()),
                ],
            },
            CxfVaultWithItems {
                vault: vault_data(VAULT_WORK),
                items: vec![
                    with_metadata(ssh_key_item()),
                    with_metadata(wifi_item()),
                    with_metadata(custom_item()),
                    with_metadata(alias_item()),
                ],
            },
        ],
        exporter_rp_id: EXPORTER_RP_ID.to_string(),
        exporter_display_name: EXPORTER_DISPLAY_NAME.to_string(),
        timestamp: EXPORT_TIMESTAMP,
    }
}

// Every item's deterministic (non-passkey) content is asserted here. Passkey key material and
// credential ids are randomly generated by the underlying authenticator on every export, so the
// baseline fixture (generated once, then committed) will never contain the same bytes as a
// freshly generated one — only the deterministic metadata (rp_id, usernames, presence) is checked.
fn assert_expected_content(result: &CxfImportResult) {
    assert!(
        result.warnings.is_empty(),
        "unexpected import warnings: {:?}",
        result.warnings
    );
    assert_eq!(result.vaults.len(), 2);

    let personal = result
        .vaults
        .iter()
        .find(|v| v.vault.as_ref().map(|v| v.name.as_str()) == Some(VAULT_PERSONAL))
        .expect("personal vault present");
    let work = result
        .vaults
        .iter()
        .find(|v| v.vault.as_ref().map(|v| v.name.as_str()) == Some(VAULT_WORK))
        .expect("work vault present");

    assert_eq!(personal.items.len(), 4);
    // The alias item has no CXF representation and is silently dropped on export.
    assert_eq!(work.items.len(), 3);
    assert!(
        work.items.iter().all(|i| i.title != ALIAS_TITLE),
        "alias item must not survive an export/import round trip"
    );

    let login = personal
        .items
        .iter()
        .find(|i| i.title == LOGIN_TITLE)
        .expect("login item present");
    let ItemContent::Login(login_content) = &login.content else {
        panic!("expected login content")
    };
    assert_eq!(login_content.email, LOGIN_EMAIL);
    assert_eq!(login_content.password, LOGIN_PASSWORD);
    assert!(login_content.totp_uri.contains(LOGIN_TOTP_SECRET));
    assert_eq!(login_content.autofill_urls.len(), 1);
    assert_eq!(login_content.autofill_urls[0].url, LOGIN_URL);
    assert_eq!(login_content.passkeys.len(), 2);
    for passkey in &login_content.passkeys {
        assert_eq!(passkey.rp_id, PASSKEY_RP_ID);
        assert!(!passkey.credential_id.is_empty());
        assert!(!passkey.content.is_empty());
    }
    let passkey_usernames: Vec<&str> = login_content.passkeys.iter().map(|p| p.user_name.as_str()).collect();
    assert!(passkey_usernames.contains(&PASSKEY_1_USER_NAME));
    assert!(passkey_usernames.contains(&PASSKEY_2_USER_NAME));
    let passkey_display_names: Vec<&str> = login_content
        .passkeys
        .iter()
        .map(|p| p.user_display_name.as_str())
        .collect();
    assert!(passkey_display_names.contains(&PASSKEY_1_USER_DISPLAY_NAME));
    assert!(passkey_display_names.contains(&PASSKEY_2_USER_DISPLAY_NAME));

    let note = personal
        .items
        .iter()
        .find(|i| i.title == NOTE_TITLE)
        .expect("note item present");
    assert_eq!(note.note, NOTE_CONTENT);
    assert!(matches!(note.content, ItemContent::Note(_)));

    let credit_card = personal
        .items
        .iter()
        .find(|i| i.title == CREDIT_CARD_TITLE)
        .expect("credit card item present");
    let ItemContent::CreditCard(cc) = &credit_card.content else {
        panic!("expected credit card content")
    };
    assert_eq!(cc.cardholder_name, CREDIT_CARD_HOLDER);
    assert_eq!(cc.number, CREDIT_CARD_NUMBER);
    assert_eq!(cc.card_type, CardType::Visa);
    assert_eq!(cc.verification_number, CREDIT_CARD_CVV);
    assert_eq!(cc.expiration_date, CREDIT_CARD_EXPIRATION);
    assert_eq!(cc.pin, CREDIT_CARD_PIN);

    let identity = personal
        .items
        .iter()
        .find(|i| i.title == IDENTITY_TITLE)
        .expect("identity item present");
    let ItemContent::Identity(identity_content) = &identity.content else {
        panic!("expected identity content")
    };
    assert_eq!(identity_content.first_name, IDENTITY_FIRST_NAME);
    assert_eq!(identity_content.last_name, IDENTITY_LAST_NAME);
    assert_eq!(identity_content.email, IDENTITY_EMAIL);
    assert_eq!(identity_content.street_address, IDENTITY_STREET_ADDRESS);
    assert_eq!(identity_content.city, IDENTITY_CITY);

    let ssh_key = work
        .items
        .iter()
        .find(|i| i.title == SSH_KEY_TITLE)
        .expect("ssh key item present");
    let ItemContent::SshKey(ssh_content) = &ssh_key.content else {
        panic!("expected ssh key content")
    };
    assert_eq!(ssh_content.public_key, SSH_PUBLIC_KEY);
    assert!(!ssh_content.private_key.is_empty());

    let wifi = work
        .items
        .iter()
        .find(|i| i.title == WIFI_TITLE)
        .expect("wifi item present");
    let ItemContent::Wifi(wifi_content) = &wifi.content else {
        panic!("expected wifi content")
    };
    assert_eq!(wifi_content.ssid, WIFI_SSID);
    assert_eq!(wifi_content.password, WIFI_PASSWORD);
    assert_eq!(wifi_content.security, WifiSecurity::WPA2);

    let custom = work
        .items
        .iter()
        .find(|i| i.title == CUSTOM_TITLE)
        .expect("custom item present");
    let ItemContent::Custom(custom_content) = &custom.content else {
        panic!("expected custom content")
    };
    let section = custom_content
        .sections
        .iter()
        .find(|s| s.section_name == CUSTOM_SECTION_NAME)
        .expect("custom section present");
    let field = section
        .section_fields
        .iter()
        .find(|f| f.name == CUSTOM_FIELD_NAME)
        .expect("custom field present");
    assert_eq!(
        field.content,
        ItemExtraFieldContent::Text(CUSTOM_FIELD_VALUE.to_string())
    );
}

#[test]
fn export_import_roundtrip() {
    let rt = runtime();
    let input = build_export_input(&rt);

    let export_result = export_cxf(input).expect("export should succeed");
    assert!(
        export_result.warnings.is_empty(),
        "unexpected export warnings: {:?}",
        export_result.warnings
    );

    let import_result = import_cxf(&export_result.payload).expect("import should succeed");
    assert_expected_content(&import_result);
}

#[test]
fn import_from_baseline_regression() {
    let payload = fs::read_to_string(BASELINE_PATH).expect("baseline fixture must exist");
    let import_result = import_cxf(&payload).expect("import should succeed");
    assert_expected_content(&import_result);
}
