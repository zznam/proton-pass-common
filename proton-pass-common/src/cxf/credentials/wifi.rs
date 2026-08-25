use credential_exchange_format::{Credential, EditableField, EditableFieldWifiNetworkSecurityType, WifiCredential};
use proton_pass_types::{WifiItem, WifiSecurity};

use crate::cxf::{
    CxfCredential, ProtonExtension,
    fields::{opt_concealed_field, opt_concealed_field_to_string, opt_field_to_string, opt_string_field},
};

fn security_to_field(
    security: &WifiSecurity,
) -> Option<EditableField<EditableFieldWifiNetworkSecurityType, ProtonExtension>> {
    let value = match security {
        WifiSecurity::UnspecifiedWifiSecurity => return None,
        WifiSecurity::WPA => EditableFieldWifiNetworkSecurityType::WpaPersonal,
        WifiSecurity::WPA2 => EditableFieldWifiNetworkSecurityType::Wpa2Personal,
        WifiSecurity::WPA3 => EditableFieldWifiNetworkSecurityType::Wpa3Personal,
        WifiSecurity::WEP => EditableFieldWifiNetworkSecurityType::Wep,
    };
    Some(EditableField {
        id: None,
        value: value.into(),
        label: None,
        extensions: None,
    })
}

fn field_to_security(
    field: Option<EditableField<EditableFieldWifiNetworkSecurityType, ProtonExtension>>,
) -> WifiSecurity {
    let Some(field) = field else {
        return WifiSecurity::UnspecifiedWifiSecurity;
    };
    match field.value.into_expected() {
        Ok(EditableFieldWifiNetworkSecurityType::WpaPersonal) => WifiSecurity::WPA,
        Ok(EditableFieldWifiNetworkSecurityType::Wpa2Personal) => WifiSecurity::WPA2,
        Ok(EditableFieldWifiNetworkSecurityType::Wpa3Personal) => WifiSecurity::WPA3,
        Ok(EditableFieldWifiNetworkSecurityType::Wep) => WifiSecurity::WEP,
        _ => WifiSecurity::UnspecifiedWifiSecurity,
    }
}

pub(crate) fn wifi_to_credential(item: &WifiItem) -> CxfCredential {
    Credential::Wifi(Box::new(WifiCredential {
        ssid: opt_string_field(&item.ssid),
        network_security_type: security_to_field(&item.security),
        passphrase: opt_concealed_field(&item.password),
        hidden: None,
    }))
}

pub(crate) fn credential_to_wifi(cred: &WifiCredential<ProtonExtension>) -> WifiItem {
    WifiItem {
        ssid: opt_field_to_string(cred.ssid.clone()),
        password: opt_concealed_field_to_string(cred.passphrase.clone()),
        security: field_to_security(cred.network_security_type.clone()),
        sections: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WifiItem {
        WifiItem {
            ssid: "MyNetwork".to_string(),
            password: "hunter2".to_string(),
            security: WifiSecurity::WPA2,
            sections: Vec::new(),
        }
    }

    #[test]
    fn wifi_round_trips() {
        let item = sample();
        let cred = wifi_to_credential(&item);
        let Credential::Wifi(cred) = cred else {
            panic!("expected wifi credential")
        };
        assert_eq!(credential_to_wifi(&cred), item);
    }

    #[test]
    fn unspecified_security_omits_field() {
        let item = WifiItem {
            ssid: "N".to_string(),
            password: "p".to_string(),
            security: WifiSecurity::UnspecifiedWifiSecurity,
            sections: Vec::new(),
        };
        let cred = wifi_to_credential(&item);
        let Credential::Wifi(cred) = cred else {
            panic!("expected wifi credential")
        };
        assert!(cred.network_security_type.is_none());
        assert_eq!(
            credential_to_wifi(&cred).security,
            WifiSecurity::UnspecifiedWifiSecurity
        );
    }

    #[test]
    fn every_security_variant_round_trips() {
        for security in [
            WifiSecurity::WPA,
            WifiSecurity::WPA2,
            WifiSecurity::WPA3,
            WifiSecurity::WEP,
        ] {
            let item = WifiItem {
                ssid: "N".to_string(),
                password: "p".to_string(),
                security: security.clone(),
                sections: Vec::new(),
            };
            let cred = wifi_to_credential(&item);
            let Credential::Wifi(cred) = cred else {
                panic!("expected wifi credential")
            };
            assert_eq!(credential_to_wifi(&cred).security, security);
        }
    }
}
