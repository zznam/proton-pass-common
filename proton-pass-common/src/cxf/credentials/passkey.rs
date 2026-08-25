use coset::iana::{Ec2KeyParameter, EllipticCurve, OkpKeyParameter};
use credential_exchange_format::{
    B64Url, Credential, Fido2Extensions, Fido2HmacCredentialAlgorithm, Fido2HmacCredentials, PasskeyCredential,
};
use ed25519_dalek::SigningKey;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use proton_pass_types::Passkey as PassPasskey;

use crate::passkey::passkey_handling::{deserialize_passkey, serialize_passkey};
use crate::passkey::{
    ProtonAlgorithm, ProtonInteger, ProtonKey, ProtonKeyType, ProtonLabel, ProtonPassCredentialExtensions,
    ProtonPassKey, ProtonPassStoredHmacSecret, ProtonRegisteredLabelKeyType, ProtonRegisteredLabelWithPrivateAlgorithm,
    ProtonValue,
};

use crate::cxf::CxfCredential;

fn find_bytes(params: &[(ProtonLabel, ProtonValue)], label: i64) -> Option<Vec<u8>> {
    params.iter().find_map(|(l, v)| match (l, v) {
        (ProtonLabel::Int(n), ProtonValue::Bytes(b)) if *n == label => Some(b.clone()),
        _ => None,
    })
}

fn hmac_secret_to_fido2_extensions(extensions: &ProtonPassCredentialExtensions) -> Option<Fido2Extensions> {
    let hmac = extensions.hmac_secret.as_ref()?;
    let cred_without_uv = hmac
        .cred_without_uv
        .clone()
        .unwrap_or_else(|| hmac.cred_with_uv.clone());
    Some(Fido2Extensions {
        hmac_credentials: Some(Fido2HmacCredentials {
            algorithm: Fido2HmacCredentialAlgorithm::HmacSha256,
            cred_with_uv: B64Url::from(hmac.cred_with_uv.clone()),
            cred_without_uv: B64Url::from(cred_without_uv),
        }),
        cred_blob: None,
        large_blob: None,
        payments: None,
    })
}

fn fido2_extensions_to_hmac_secret(extensions: Option<&Fido2Extensions>) -> ProtonPassCredentialExtensions {
    let hmac_secret = extensions.and_then(|ext| ext.hmac_credentials.as_ref()).map(|hmac| {
        let cred_with_uv = Vec::from(hmac.cred_with_uv.clone());
        let cred_without_uv = Vec::from(hmac.cred_without_uv.clone());
        let cred_without_uv = (cred_without_uv != cred_with_uv).then_some(cred_without_uv);
        ProtonPassStoredHmacSecret {
            cred_with_uv,
            cred_without_uv,
        }
    });
    ProtonPassCredentialExtensions { hmac_secret }
}

pub(crate) fn passkey_to_credential(passkey: &PassPasskey) -> Result<CxfCredential, String> {
    let proton_pass_key = deserialize_passkey(&passkey.content).map_err(|e| format!("{e:?}"))?;
    let key = &proton_pass_key.key;

    let der = match &key.kty {
        ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::EC2) => {
            let d =
                find_bytes(&key.params, Ec2KeyParameter::D as i64).ok_or("EC2 key is missing its private scalar")?;
            let secret = SecretKey::from_slice(&d).map_err(|e| format!("invalid EC2 private scalar: {e}"))?;
            let doc = secret
                .to_pkcs8_der()
                .map_err(|e| format!("failed to encode EC2 key as PKCS#8: {e}"))?;
            doc.as_bytes().to_vec()
        }
        ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::OKP) => {
            let d = find_bytes(&key.params, OkpKeyParameter::D as i64).ok_or("OKP key is missing its private seed")?;
            let seed: [u8; 32] = d
                .as_slice()
                .try_into()
                .map_err(|_| "Ed25519 private seed must be 32 bytes".to_string())?;
            let signing_key = SigningKey::from_bytes(&seed);
            let doc = signing_key
                .to_pkcs8_der()
                .map_err(|e| format!("failed to encode OKP key as PKCS#8: {e}"))?;
            doc.as_bytes().to_vec()
        }
        other => return Err(format!("unsupported passkey key type: {other:?}")),
    };

    Ok(Credential::Passkey(Box::new(PasskeyCredential {
        credential_id: B64Url::from(passkey.credential_id.clone()),
        rp_id: passkey.rp_id.clone(),
        username: passkey.user_name.clone(),
        user_display_name: passkey.user_display_name.clone(),
        user_handle: B64Url::from(passkey.user_handle.clone()),
        key: B64Url::from(der),
        fido2_extensions: hmac_secret_to_fido2_extensions(&proton_pass_key.extensions),
    })))
}

pub(crate) fn credential_to_passkey(cred: &PasskeyCredential) -> Result<PassPasskey, String> {
    let der: Vec<u8> = cred.key.clone().into();

    let (kty, alg, params) = if let Ok(secret) = SecretKey::from_pkcs8_der(&der) {
        let d = secret.to_bytes().to_vec();
        let public_point = secret.public_key().to_encoded_point(false);
        let x = public_point
            .x()
            .ok_or("EC2 public key is missing its x coordinate")?
            .to_vec();
        let y = public_point
            .y()
            .ok_or("EC2 public key is missing its y coordinate")?
            .to_vec();
        (
            ProtonKeyType::EC2,
            ProtonAlgorithm::ES256,
            vec![
                (
                    ProtonLabel::Int(Ec2KeyParameter::Crv as i64),
                    ProtonValue::Integer(ProtonInteger::from(EllipticCurve::P_256 as i128)),
                ),
                (ProtonLabel::Int(Ec2KeyParameter::X as i64), ProtonValue::Bytes(x)),
                (ProtonLabel::Int(Ec2KeyParameter::Y as i64), ProtonValue::Bytes(y)),
                (ProtonLabel::Int(Ec2KeyParameter::D as i64), ProtonValue::Bytes(d)),
            ],
        )
    } else if let Ok(signing_key) = SigningKey::from_pkcs8_der(&der) {
        let d = signing_key.to_bytes().to_vec();
        let x = signing_key.verifying_key().to_bytes().to_vec();
        (
            ProtonKeyType::OKP,
            ProtonAlgorithm::EdDSA,
            vec![
                (
                    ProtonLabel::Int(OkpKeyParameter::Crv as i64),
                    ProtonValue::Integer(ProtonInteger::from(EllipticCurve::Ed25519 as i128)),
                ),
                (ProtonLabel::Int(OkpKeyParameter::X as i64), ProtonValue::Bytes(x)),
                (ProtonLabel::Int(OkpKeyParameter::D as i64), ProtonValue::Bytes(d)),
            ],
        )
    } else {
        return Err("could not decode the passkey's PKCS#8 key as EC P-256 or Ed25519".to_string());
    };

    let key = ProtonKey {
        kty: ProtonRegisteredLabelKeyType::Assigned(kty),
        key_id: Vec::new(),
        alg: Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(alg)),
        key_ops: Vec::new(),
        base_iv: Vec::new(),
        params,
    };

    let proton_pass_key = ProtonPassKey {
        key,
        credential_id: Vec::from(cred.credential_id.clone()),
        rp_id: cred.rp_id.clone(),
        user_handle: Some(Vec::from(cred.user_handle.clone())),
        counter: Some(0),
        extensions: fido2_extensions_to_hmac_secret(cred.fido2_extensions.as_ref()),
        user_display_name: Some(cred.user_display_name.clone()),
        username: Some(cred.username.clone()),
    };

    let content = serialize_passkey(&proton_pass_key).map_err(|e| format!("{e:?}"))?;

    Ok(PassPasskey {
        key_id: String::from(cred.credential_id.clone()),
        content,
        domain: cred.rp_id.clone(),
        rp_id: cred.rp_id.clone(),
        rp_name: String::new(),
        user_name: cred.username.clone(),
        user_display_name: cred.user_display_name.clone(),
        user_id: Vec::from(cred.user_handle.clone()),
        create_time: 0,
        note: String::new(),
        credential_id: Vec::from(cred.credential_id.clone()),
        user_handle: Vec::from(cred.user_handle.clone()),
        creation_data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::passkey_handling::serialize_passkey;

    fn sample_ec2_key() -> ProtonKey {
        let scalar: [u8; 32] = [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
        ];
        let secret = SecretKey::from_slice(&scalar).unwrap();
        let public_point = secret.public_key().to_encoded_point(false);
        ProtonKey {
            kty: ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::EC2),
            key_id: Vec::new(),
            alg: Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
                ProtonAlgorithm::ES256,
            )),
            key_ops: Vec::new(),
            base_iv: Vec::new(),
            params: vec![
                (
                    ProtonLabel::Int(Ec2KeyParameter::Crv as i64),
                    ProtonValue::Integer(ProtonInteger::from(EllipticCurve::P_256 as i128)),
                ),
                (
                    ProtonLabel::Int(Ec2KeyParameter::X as i64),
                    ProtonValue::Bytes(public_point.x().unwrap().to_vec()),
                ),
                (
                    ProtonLabel::Int(Ec2KeyParameter::Y as i64),
                    ProtonValue::Bytes(public_point.y().unwrap().to_vec()),
                ),
                (
                    ProtonLabel::Int(Ec2KeyParameter::D as i64),
                    ProtonValue::Bytes(secret.to_bytes().to_vec()),
                ),
            ],
        }
    }

    fn sample_okp_key() -> ProtonKey {
        let seed: [u8; 32] = [
            0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0x10, 0x21,
            0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
        ];
        let signing_key = SigningKey::from_bytes(&seed);
        ProtonKey {
            kty: ProtonRegisteredLabelKeyType::Assigned(ProtonKeyType::OKP),
            key_id: Vec::new(),
            alg: Some(ProtonRegisteredLabelWithPrivateAlgorithm::Assigned(
                ProtonAlgorithm::EdDSA,
            )),
            key_ops: Vec::new(),
            base_iv: Vec::new(),
            params: vec![
                (
                    ProtonLabel::Int(OkpKeyParameter::Crv as i64),
                    ProtonValue::Integer(ProtonInteger::from(EllipticCurve::Ed25519 as i128)),
                ),
                (
                    ProtonLabel::Int(OkpKeyParameter::X as i64),
                    ProtonValue::Bytes(signing_key.verifying_key().to_bytes().to_vec()),
                ),
                (
                    ProtonLabel::Int(OkpKeyParameter::D as i64),
                    ProtonValue::Bytes(signing_key.to_bytes().to_vec()),
                ),
            ],
        }
    }

    fn sample_passkey(key: ProtonKey) -> PassPasskey {
        let proton_pass_key = ProtonPassKey {
            key,
            credential_id: vec![1, 2, 3, 4],
            rp_id: "example.com".to_string(),
            user_handle: Some(vec![5, 6, 7, 8]),
            counter: Some(0),
            extensions: ProtonPassCredentialExtensions::default(),
            user_display_name: Some("Jane Doe".to_string()),
            username: Some("jane".to_string()),
        };
        let content = serialize_passkey(&proton_pass_key).unwrap();
        PassPasskey {
            key_id: "key-01".to_string(),
            content,
            domain: "example.com".to_string(),
            rp_id: "example.com".to_string(),
            rp_name: "Example".to_string(),
            user_name: "jane".to_string(),
            user_display_name: "Jane Doe".to_string(),
            user_id: vec![5, 6, 7, 8],
            create_time: 0,
            note: String::new(),
            credential_id: vec![1, 2, 3, 4],
            user_handle: vec![5, 6, 7, 8],
            creation_data: None,
        }
    }

    #[test]
    fn ec2_key_round_trips_through_pkcs8() {
        let passkey = sample_passkey(sample_ec2_key());
        let cred = passkey_to_credential(&passkey).unwrap();
        let Credential::Passkey(cred) = cred else {
            panic!("expected passkey credential")
        };
        assert_eq!(cred.rp_id.clone(), passkey.rp_id);

        let back = credential_to_passkey(&cred).unwrap();
        let original_key = deserialize_passkey(&passkey.content).unwrap();
        let round_tripped_key = deserialize_passkey(&back.content).unwrap();

        let d = |k: &ProtonKey| find_bytes(&k.params, Ec2KeyParameter::D as i64).unwrap();
        assert_eq!(d(&original_key.key), d(&round_tripped_key.key));
        assert_eq!(original_key.key.kty, round_tripped_key.key.kty);
    }

    #[test]
    fn okp_key_round_trips_through_pkcs8() {
        let passkey = sample_passkey(sample_okp_key());
        let cred = passkey_to_credential(&passkey).unwrap();
        let Credential::Passkey(cred) = cred else {
            panic!("expected passkey credential")
        };

        let back = credential_to_passkey(&cred).unwrap();
        let original_key = deserialize_passkey(&passkey.content).unwrap();
        let round_tripped_key = deserialize_passkey(&back.content).unwrap();

        let d = |k: &ProtonKey| find_bytes(&k.params, OkpKeyParameter::D as i64).unwrap();
        assert_eq!(d(&original_key.key), d(&round_tripped_key.key));
        assert_eq!(original_key.key.kty, round_tripped_key.key.kty);
    }

    #[test]
    fn passkey_metadata_round_trips() {
        let passkey = sample_passkey(sample_ec2_key());
        let cred = passkey_to_credential(&passkey).unwrap();
        let Credential::Passkey(cred) = cred else {
            panic!("expected passkey credential")
        };
        let back = credential_to_passkey(&cred).unwrap();

        assert_eq!(back.rp_id, passkey.rp_id);
        assert_eq!(back.user_name, passkey.user_name);
        assert_eq!(back.user_display_name, passkey.user_display_name);
        assert_eq!(back.credential_id, passkey.credential_id);
        assert_eq!(back.user_handle, passkey.user_handle);
    }

    #[test]
    fn hmac_secret_round_trips() {
        let cred_with_uv = vec![1, 1, 1];
        let cred_without_uv = vec![2, 2, 2];

        let mut passkey = sample_passkey(sample_ec2_key());
        let mut key = deserialize_passkey(&passkey.content).unwrap();
        key.extensions = ProtonPassCredentialExtensions {
            hmac_secret: Some(ProtonPassStoredHmacSecret {
                cred_with_uv: cred_with_uv.clone(),
                cred_without_uv: Some(cred_without_uv.clone()),
            }),
        };
        passkey.content = serialize_passkey(&key).unwrap();

        let cred = passkey_to_credential(&passkey).unwrap();
        let Credential::Passkey(cred) = cred else {
            panic!("expected passkey credential")
        };
        let hmac = cred
            .fido2_extensions
            .as_ref()
            .unwrap()
            .hmac_credentials
            .as_ref()
            .unwrap();
        assert_eq!(Vec::from(hmac.cred_with_uv.clone()), cred_with_uv);
        assert_eq!(Vec::from(hmac.cred_without_uv.clone()), cred_without_uv);

        let back = credential_to_passkey(&cred).unwrap();
        let back_key = deserialize_passkey(&back.content).unwrap();
        let back_hmac = back_key.extensions.hmac_secret.unwrap();
        assert_eq!(back_hmac.cred_with_uv, cred_with_uv);
        assert_eq!(back_hmac.cred_without_uv, Some(cred_without_uv));
    }

    #[test]
    fn missing_cred_without_uv_is_restored_as_none_after_round_trip() {
        let cred_with_uv = vec![1, 1, 1];

        let mut passkey = sample_passkey(sample_ec2_key());
        let mut key = deserialize_passkey(&passkey.content).unwrap();
        key.extensions = ProtonPassCredentialExtensions {
            hmac_secret: Some(ProtonPassStoredHmacSecret {
                cred_with_uv: cred_with_uv.clone(),
                cred_without_uv: None,
            }),
        };
        passkey.content = serialize_passkey(&key).unwrap();

        let cred = passkey_to_credential(&passkey).unwrap();
        let Credential::Passkey(cred) = cred else {
            panic!("expected passkey credential")
        };
        let hmac = cred
            .fido2_extensions
            .as_ref()
            .unwrap()
            .hmac_credentials
            .as_ref()
            .unwrap();
        assert_eq!(Vec::from(hmac.cred_without_uv.clone()), cred_with_uv);

        let back = credential_to_passkey(&cred).unwrap();
        let back_key = deserialize_passkey(&back.content).unwrap();
        let back_hmac = back_key.extensions.hmac_secret.unwrap();
        assert_eq!(back_hmac.cred_with_uv, cred_with_uv);
        assert_eq!(back_hmac.cred_without_uv, None);
    }

    #[test]
    fn malformed_pkcs8_is_rejected() {
        let cred = PasskeyCredential {
            credential_id: B64Url::from(vec![1]),
            rp_id: "example.com".to_string(),
            username: "u".to_string(),
            user_display_name: "U".to_string(),
            user_handle: B64Url::from(vec![2]),
            key: B64Url::from(vec![9, 9, 9]),
            fido2_extensions: None,
        };
        assert!(credential_to_passkey(&cred).is_err());
    }
}
