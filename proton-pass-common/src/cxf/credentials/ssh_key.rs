use credential_exchange_format::{
    B64Url, Credential, CustomFieldsCredential, EditableField, EditableFieldValue, SshKeyCredential,
};
use proton_pass_types::SshKeyItem;

use crate::cxf::{CxfCredential, CxfWarning, CxfWarningKind, ProtonExtension};

pub(crate) const PUBLIC_KEY_FIELD_LABEL: &str = "public_key";

pub(crate) fn ssh_key_to_credential(
    item: &SshKeyItem,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> Option<CxfCredential> {
    let key_type = match ssh_key::PrivateKey::from_openssh(&item.private_key) {
        Ok(key) => key.algorithm().to_string(),
        Err(_) => {
            warnings.push(CxfWarning {
                item_title: item_title.map(str::to_string),
                message: "Could not export SSH key: unrecognized or unsupported key algorithm".to_string(),
                kind: CxfWarningKind::UnsupportedCredential,
            });
            return None;
        }
    };

    Some(Credential::SshKey(Box::new(SshKeyCredential {
        key_type,
        private_key: B64Url::from(item.private_key.as_bytes()),
        key_comment: None,
        creation_date: None,
        expiry_date: None,
        key_generation_source: None,
    })))
}

pub(crate) fn public_key_to_credential(public_key: &str) -> Option<CxfCredential> {
    if public_key.is_empty() {
        return None;
    }
    Some(Credential::CustomFields(Box::new(CustomFieldsCredential {
        id: None,
        label: None,
        fields: vec![EditableFieldValue::String(EditableField {
            id: None,
            value: credential_exchange_format::EditableFieldString(public_key.to_string()).into(),
            label: Some(PUBLIC_KEY_FIELD_LABEL.to_string()),
            extensions: None,
        })],
        extensions: Vec::new(),
    })))
}

pub(crate) fn extract_public_key(cred: &CustomFieldsCredential<ProtonExtension>) -> Option<String> {
    cred.fields.iter().find_map(|field| match field {
        EditableFieldValue::String(f) if f.label.as_deref() == Some(PUBLIC_KEY_FIELD_LABEL) => {
            Some(f.value.clone().into())
        }
        _ => None,
    })
}

pub(crate) fn credential_to_ssh_key(
    cred: &SshKeyCredential<ProtonExtension>,
    public_key: String,
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> Option<SshKeyItem> {
    let private_key = match String::from_utf8(Vec::from(cred.private_key.clone())) {
        Ok(key) => key,
        Err(_) => {
            warnings.push(CxfWarning {
                item_title: item_title.map(str::to_string),
                message: "Could not import SSH private key: not valid UTF-8".to_string(),
                kind: CxfWarningKind::MalformedInput,
            });
            return None;
        }
    };

    if ssh_key::PrivateKey::from_openssh(&private_key).is_err() {
        warnings.push(CxfWarning {
            item_title: item_title.map(str::to_string),
            message: "Could not verify the SSH key algorithm: imported as-is".to_string(),
            kind: CxfWarningKind::UnsupportedCredential,
        });
    }

    Some(SshKeyItem {
        private_key,
        public_key,
        sections: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_ed25519_openssh_key() -> String {
        let keypair = ssh_key::private::Ed25519Keypair::random(&mut rand::rng());
        ssh_key::PrivateKey::from(keypair)
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn private_key_round_trips_as_opaque_bytes() {
        let private_key = generate_ed25519_openssh_key();
        let item = SshKeyItem {
            private_key,
            public_key: "ssh-ed25519 AAAA".to_string(),
            sections: Vec::new(),
        };
        let mut warnings = Vec::new();
        let cred = ssh_key_to_credential(&item, None, &mut warnings).unwrap();
        let Credential::SshKey(cred) = cred else {
            panic!("expected ssh key credential")
        };
        assert!(warnings.is_empty());
        let back = credential_to_ssh_key(&cred, item.public_key.clone(), None, &mut warnings).unwrap();
        assert_eq!(back.private_key, item.private_key);
        assert!(warnings.is_empty());
    }

    #[test]
    fn public_key_round_trips_via_custom_fields_credential() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".to_string();
        let cred = public_key_to_credential(&public_key).unwrap();
        let Credential::CustomFields(cred) = cred else {
            panic!("expected custom fields credential")
        };
        assert_eq!(extract_public_key(&cred), Some(public_key));
    }

    #[test]
    fn empty_public_key_produces_no_credential() {
        assert!(public_key_to_credential("").is_none());
    }

    #[test]
    fn unparseable_private_key_is_not_exported_and_produces_warning() {
        let mut warnings = Vec::new();
        let cred = ssh_key_to_credential(
            &SshKeyItem {
                private_key: "not a real key".to_string(),
                public_key: String::new(),
                sections: Vec::new(),
            },
            Some("My SSH key"),
            &mut warnings,
        );
        assert!(cred.is_none());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, CxfWarningKind::UnsupportedCredential);
        assert_eq!(warnings[0].item_title.as_deref(), Some("My SSH key"));
    }

    #[test]
    fn unparseable_private_key_is_kept_with_unsupported_credential_warning_on_import() {
        let cred = SshKeyCredential {
            key_type: "unknown".to_string(),
            private_key: B64Url::from("not a real key".as_bytes()),
            key_comment: None,
            creation_date: None,
            expiry_date: None,
            key_generation_source: None,
        };
        let mut warnings = Vec::new();
        let back = credential_to_ssh_key(&cred, String::new(), Some("My SSH key"), &mut warnings).unwrap();
        assert_eq!(back.private_key, "not a real key");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, CxfWarningKind::UnsupportedCredential);
        assert_eq!(warnings[0].item_title.as_deref(), Some("My SSH key"));
    }

    #[test]
    fn invalid_utf8_private_key_is_dropped_with_malformed_input_warning() {
        let cred = SshKeyCredential {
            key_type: "unknown".to_string(),
            private_key: B64Url::from([0xFF, 0xFE].as_slice()),
            key_comment: None,
            creation_date: None,
            expiry_date: None,
            key_generation_source: None,
        };
        let mut warnings = Vec::new();
        let back = credential_to_ssh_key(&cred, String::new(), Some("My SSH key"), &mut warnings);
        assert!(back.is_none());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, CxfWarningKind::MalformedInput);
    }
}
