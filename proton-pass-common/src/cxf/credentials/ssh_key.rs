use credential_exchange_format::{
    B64Url, Credential, CustomFieldsCredential, EditableField, EditableFieldValue, SshKeyCredential,
};
use proton_pass_types::SshKeyItem;

use crate::cxf::{CxfCredential, CxfWarning, CxfWarningKind, ProtonExtension};

pub(crate) const PUBLIC_KEY_FIELD_LABEL: &str = "public_key";

fn detect_key_type(private_key: &str) -> String {
    ssh_key::PrivateKey::from_openssh(private_key)
        .map(|key| key.algorithm().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub(crate) fn ssh_key_to_credential(item: &SshKeyItem) -> CxfCredential {
    Credential::SshKey(Box::new(SshKeyCredential {
        key_type: detect_key_type(&item.private_key),
        private_key: B64Url::from(item.private_key.as_bytes()),
        key_comment: None,
        creation_date: None,
        expiry_date: None,
        key_generation_source: None,
    }))
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
) -> SshKeyItem {
    let private_key = String::from_utf8(Vec::from(cred.private_key.clone())).unwrap_or_else(|_| {
        warnings.push(CxfWarning {
            item_title: item_title.map(str::to_string),
            message: "Could not import SSH private key: not valid UTF-8".to_string(),
            kind: CxfWarningKind::MalformedInput,
        });
        String::new()
    });
    SshKeyItem {
        private_key,
        public_key,
        sections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_round_trips_as_opaque_bytes() {
        let item = SshKeyItem {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            sections: Vec::new(),
        };
        let cred = ssh_key_to_credential(&item);
        let Credential::SshKey(cred) = cred else {
            panic!("expected ssh key credential")
        };
        let mut warnings = Vec::new();
        let back = credential_to_ssh_key(&cred, item.public_key.clone(), None, &mut warnings);
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
    fn unparseable_private_key_falls_back_to_unknown_type() {
        let cred = ssh_key_to_credential(&SshKeyItem {
            private_key: "not a real key".to_string(),
            public_key: String::new(),
            sections: Vec::new(),
        });
        let Credential::SshKey(cred) = cred else {
            panic!("expected ssh key credential")
        };
        assert_eq!(cred.key_type, "unknown");
    }
}
