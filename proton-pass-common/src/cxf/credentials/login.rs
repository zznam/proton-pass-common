use credential_exchange_format::{
    B32, BasicAuthCredential, Credential, CredentialScope, CustomFieldsCredential, EditableField, EditableFieldString,
    EditableFieldValue, GeneratedPasswordCredential, OTPHashAlgorithm, TotpCredential,
};
use proton_pass_totp::{Algorithm as PassAlgorithm, TOTP};
use proton_pass_types::{AutofillUrl, AutofillUrlMode, LoginItem};

use crate::cxf::{
    CxfCredential, CxfWarning, CxfWarningKind, ProtonExtension,
    fields::{concealed_field, concealed_field_to_string, opt_field_to_string, opt_string_field},
};

pub(crate) const EMAIL_FIELD_LABEL: &str = "email";
pub(crate) const USERNAME_FIELD_LABEL: &str = "username";

pub(crate) fn login_basics_to_credential(item: &LoginItem) -> CxfCredential {
    let username = if !item.email.is_empty() {
        item.email.clone()
    } else {
        item.username.clone()
    };

    Credential::BasicAuth(Box::new(BasicAuthCredential {
        username: opt_string_field(&username),
        password: (!item.password.is_empty()).then(|| concealed_field(item.password.clone())),
    }))
}

pub(crate) fn login_identifiers_credential(item: &LoginItem) -> Option<CxfCredential> {
    let mut fields = Vec::new();
    if !item.email.is_empty() {
        fields.push(EditableFieldValue::String(EditableField {
            id: None,
            value: EditableFieldString(item.email.clone()).into(),
            label: Some(EMAIL_FIELD_LABEL.to_string()),
            extensions: None,
        }));
    }
    if !item.username.is_empty() {
        fields.push(EditableFieldValue::String(EditableField {
            id: None,
            value: EditableFieldString(item.username.clone()).into(),
            label: Some(USERNAME_FIELD_LABEL.to_string()),
            extensions: None,
        }));
    }
    if fields.is_empty() {
        return None;
    }
    Some(Credential::CustomFields(Box::new(CustomFieldsCredential {
        id: None,
        label: None,
        fields,
        extensions: Vec::new(),
    })))
}

pub(crate) fn extract_login_identifiers(credentials: &[CxfCredential]) -> (Option<String>, Option<String>) {
    let mut email = None;
    let mut username = None;
    for field in credentials
        .iter()
        .filter_map(|cred| match cred {
            Credential::CustomFields(cf) if cf.label.is_none() => Some(cf.fields.iter()),
            _ => None,
        })
        .flatten()
    {
        let EditableFieldValue::String(f) = field else {
            continue;
        };
        match f.label.as_deref() {
            Some(EMAIL_FIELD_LABEL) => email = Some(f.value.clone().into()),
            Some(USERNAME_FIELD_LABEL) => username = Some(f.value.clone().into()),
            _ => {}
        }
    }
    (email, username)
}

pub(crate) fn credential_to_login_basics(cred: &BasicAuthCredential<ProtonExtension>) -> LoginItem {
    let value = opt_field_to_string(cred.username.clone());
    let (email, username) = if crate::email::is_email_valid(&value) {
        (value, String::new())
    } else {
        (String::new(), value)
    };
    LoginItem {
        email,
        username,
        password: cred.password.clone().map(concealed_field_to_string).unwrap_or_default(),
        urls: Vec::new(),
        totp_uri: String::new(),
        passkeys: Vec::new(),
        autofill_urls: Vec::new(),
    }
}

pub(crate) fn generated_password_to_login(cred: &GeneratedPasswordCredential) -> LoginItem {
    LoginItem {
        email: String::new(),
        username: String::new(),
        password: cred.password.clone(),
        urls: Vec::new(),
        totp_uri: String::new(),
        passkeys: Vec::new(),
        autofill_urls: Vec::new(),
    }
}

pub(crate) fn urls_to_scope(urls: &[String]) -> Option<CredentialScope> {
    if urls.is_empty() {
        return None;
    }
    Some(CredentialScope {
        urls: urls.to_vec(),
        android_apps: Vec::new(),
    })
}

pub(crate) fn scope_to_autofill_urls(scope: Option<&CredentialScope>) -> Vec<AutofillUrl> {
    scope
        .map(|scope| {
            scope
                .urls
                .iter()
                .map(|url| AutofillUrl {
                    url: url.clone(),
                    mode: AutofillUrlMode::Default,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn pass_algorithm_to_cxf(algorithm: PassAlgorithm) -> OTPHashAlgorithm {
    match algorithm {
        PassAlgorithm::SHA1 => OTPHashAlgorithm::Sha1,
        PassAlgorithm::SHA256 => OTPHashAlgorithm::Sha256,
        PassAlgorithm::SHA512 => OTPHashAlgorithm::Sha512,
    }
}

pub(crate) fn totp_uri_to_credential(
    uri: &str,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> Option<CxfCredential> {
    let totp = TOTP::from_uri(uri).ok()?;
    if totp.secret.is_empty() {
        return None;
    }
    let secret = B32::try_from(totp.secret.as_str()).ok()?;

    let period = totp.get_period();
    if period > u16::from(u8::MAX) {
        warnings.push(CxfWarning {
            item_title: item_title.map(str::to_string),
            message: format!(
                "TOTP period of {period}s exceeds the CXF format's maximum of {}s and was clamped",
                u8::MAX
            ),
            kind: CxfWarningKind::MalformedInput,
        });
    }

    Some(Credential::Totp(Box::new(TotpCredential {
        secret,
        period: period.min(u16::from(u8::MAX)) as u8,
        digits: totp.get_digits(),
        username: totp.label.clone(),
        algorithm: pass_algorithm_to_cxf(totp.get_algorithm()),
        issuer: totp.issuer.clone(),
    })))
}

pub(crate) fn credential_to_totp_uri(
    cred: &TotpCredential,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> String {
    let algorithm = match &cred.algorithm {
        OTPHashAlgorithm::Sha1 => PassAlgorithm::SHA1,
        OTPHashAlgorithm::Sha256 => PassAlgorithm::SHA256,
        OTPHashAlgorithm::Sha512 => PassAlgorithm::SHA512,
        _ => {
            warnings.push(CxfWarning {
                item_title: item_title.map(str::to_string),
                message: "Unknown TOTP hash algorithm, defaulting to SHA1".to_string(),
                kind: CxfWarningKind::MalformedInput,
            });
            PassAlgorithm::SHA1
        }
    };

    let totp = TOTP {
        label: cred.username.clone(),
        secret: String::from(cred.secret.clone()),
        issuer: cred.issuer.clone(),
        algorithm: Some(algorithm),
        digits: Some(cred.digits),
        period: Some(cred.period as u16),
    };
    totp.to_uri(None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_basics_prefers_email_when_both_set_and_equal() {
        let email = "a@b.com";
        let item = LoginItem {
            email: email.to_string(),
            username: email.to_string(),
            password: "pw".to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let cred = login_basics_to_credential(&item);
        let Credential::BasicAuth(cred) = cred else {
            panic!("expected basic auth credential")
        };
        assert_eq!(opt_field_to_string(cred.username), email);
    }

    #[test]
    fn login_identifiers_credential_carries_both_email_and_username() {
        let email = "a@b.com";
        let username = "different_username";
        let item = LoginItem {
            email: email.to_string(),
            username: username.to_string(),
            password: String::new(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let cred = login_identifiers_credential(&item).expect("identifiers credential present");
        let Credential::CustomFields(cred) = cred else {
            panic!("expected custom fields credential")
        };
        assert!(cred.label.is_none());

        let (extracted_email, extracted_username) = extract_login_identifiers(&[Credential::CustomFields(cred)]);
        assert_eq!(extracted_email.as_deref(), Some(email));
        assert_eq!(extracted_username.as_deref(), Some(username));
    }

    #[test]
    fn username_only_login_identifiers_credential_has_no_email_field() {
        let username = "just_a_username";
        let item = LoginItem {
            email: String::new(),
            username: username.to_string(),
            password: String::new(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let cred = login_identifiers_credential(&item).expect("identifiers credential present");
        let (extracted_email, extracted_username) = extract_login_identifiers(&[cred]);
        assert_eq!(extracted_email, None);
        assert_eq!(extracted_username.as_deref(), Some(username));
    }

    #[test]
    fn empty_login_has_no_identifiers_credential() {
        let item = LoginItem {
            email: String::new(),
            username: String::new(),
            password: "pw".to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        assert!(login_identifiers_credential(&item).is_none());
    }

    #[test]
    fn password_round_trips() {
        let email = "user@example.com";
        let password = "hunter2";
        let item = LoginItem {
            email: email.to_string(),
            username: String::new(),
            password: password.to_string(),
            urls: Vec::new(),
            totp_uri: String::new(),
            passkeys: Vec::new(),
            autofill_urls: Vec::new(),
        };
        let cred = login_basics_to_credential(&item);
        let Credential::BasicAuth(cred) = cred else {
            panic!("expected basic auth credential")
        };
        let back = credential_to_login_basics(&cred);
        assert_eq!(back.password, password);
        assert_eq!(back.email, email);
    }

    #[test]
    fn non_email_basic_auth_username_is_routed_to_username_not_email() {
        let cred = BasicAuthCredential {
            username: opt_string_field("bob"),
            password: None,
        };
        let back = credential_to_login_basics(&cred);
        assert!(back.email.is_empty());
        assert_eq!(back.username, "bob");
    }

    #[test]
    fn email_shaped_basic_auth_username_is_routed_to_email() {
        let cred = BasicAuthCredential {
            username: opt_string_field("bob@example.com"),
            password: None,
        };
        let back = credential_to_login_basics(&cred);
        assert_eq!(back.email, "bob@example.com");
        assert!(back.username.is_empty());
    }

    #[test]
    fn generated_password_becomes_login_password() {
        let password = "generated123";
        let cred = GeneratedPasswordCredential {
            password: password.to_string(),
        };
        let login = generated_password_to_login(&cred);
        assert_eq!(login.password, password);
        assert!(login.email.is_empty());
        assert!(login.username.is_empty());
    }

    #[test]
    fn urls_round_trip_through_scope() {
        let urls = vec!["https://example.com".to_string(), "https://other.com".to_string()];
        let scope = urls_to_scope(&urls).unwrap();
        let autofill = scope_to_autofill_urls(Some(&scope));
        let back: Vec<String> = autofill.iter().map(|a| a.url.clone()).collect();
        assert_eq!(back, urls);
        assert!(autofill.iter().all(|a| a.mode == AutofillUrlMode::Default));
    }

    #[test]
    fn empty_urls_produce_no_scope() {
        assert!(urls_to_scope(&[]).is_none());
    }

    #[test]
    fn primary_totp_round_trips() {
        let secret = "JBSWY3DPEHPK3PXP";
        let issuer = "Proton";
        let digits: u8 = 8;
        let period: u8 = 45;
        let uri = format!(
            "otpauth://totp/jane.doe?secret={secret}&issuer={issuer}&algorithm=SHA256&digits={digits}&period={period}"
        );
        let mut export_warnings = Vec::new();
        let cred = totp_uri_to_credential(&uri, None, &mut export_warnings).unwrap();
        let Credential::Totp(cred) = cred else {
            panic!("expected totp credential")
        };
        assert_eq!(cred.digits, digits);
        assert_eq!(cred.period, period);
        assert_eq!(cred.algorithm, OTPHashAlgorithm::Sha256);
        assert_eq!(cred.issuer.as_deref(), Some(issuer));
        assert!(export_warnings.is_empty());

        let mut warnings = Vec::new();
        let back = credential_to_totp_uri(&cred, None, &mut warnings);
        let reparsed = TOTP::from_uri(&back).unwrap();
        assert_eq!(reparsed.secret, secret);
        assert_eq!(reparsed.get_digits(), digits);
        assert_eq!(reparsed.get_period(), u16::from(period));
        assert_eq!(reparsed.algorithm, Some(PassAlgorithm::SHA256));
        assert_eq!(reparsed.issuer.as_deref(), Some(issuer));
        assert!(warnings.is_empty());
    }

    #[test]
    fn hotp_uri_is_rejected() {
        let uri = "otpauth://hotp/jane.doe?secret=JBSWY3DPEHPK3PXP&counter=1";
        assert!(totp_uri_to_credential(uri, None, &mut Vec::new()).is_none());
    }

    #[test]
    fn unknown_algorithm_defaults_to_sha1_with_warning() {
        let cred = TotpCredential {
            secret: B32::try_from("JBSWY3DPEHPK3PXP").unwrap(),
            period: 30,
            digits: 6,
            username: None,
            algorithm: OTPHashAlgorithm::Unknown("SHA3".to_string()),
            issuer: None,
        };
        let mut warnings = Vec::new();
        let uri = credential_to_totp_uri(&cred, Some("Item"), &mut warnings);
        let reparsed = TOTP::from_uri(&uri).unwrap();
        assert_eq!(reparsed.algorithm, Some(PassAlgorithm::SHA1));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, CxfWarningKind::MalformedInput);
    }

    #[test]
    fn empty_secret_totp_uri_is_ignored() {
        assert!(totp_uri_to_credential("", None, &mut Vec::new()).is_none());
    }

    #[test]
    fn period_over_u8_max_is_clamped_with_warning() {
        let uri = "otpauth://totp/jane.doe?secret=JBSWY3DPEHPK3PXP&period=300";
        let mut warnings = Vec::new();
        let cred = totp_uri_to_credential(uri, Some("Item"), &mut warnings).unwrap();
        let Credential::Totp(cred) = cred else {
            panic!("expected totp credential")
        };
        assert_eq!(cred.period, u8::MAX);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, CxfWarningKind::MalformedInput);
    }
}
