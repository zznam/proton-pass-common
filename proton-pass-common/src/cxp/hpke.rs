use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use jose_jwk::{Jwk, Key, Okp, OkpCurves, Parameters};
use zeroize::Zeroizing;

use credential_exchange_protocol::{HpkeAead, HpkeKdf, HpkeKem, HpkeMode, HpkeParameters};

use super::CxpError;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

pub(crate) fn supported_parameters(key: Option<Jwk>) -> HpkeParameters {
    HpkeParameters {
        mode: HpkeMode::Base,
        kem: HpkeKem::DhX25519,
        kdf: HpkeKdf::HkdfSha256,
        aead: HpkeAead::ChaCha20Poly1305,
        key,
    }
}

pub(crate) fn is_supported(params: &HpkeParameters) -> bool {
    *params == supported_parameters(None)
}

pub(crate) struct GeneratedKeyPair {
    pub private_key: Zeroizing<Vec<u8>>,
    pub public_jwk: Jwk,
}

pub(crate) fn generate_keypair() -> GeneratedKeyPair {
    let (private_key, public_key) = Kem::gen_keypair();
    GeneratedKeyPair {
        private_key: Zeroizing::new(private_key.to_bytes().to_vec()),
        public_jwk: x25519_bytes_to_jwk(&public_key.to_bytes()),
    }
}

fn x25519_bytes_to_jwk(bytes: &[u8]) -> Jwk {
    Jwk {
        key: Key::Okp(Okp {
            crv: OkpCurves::X25519,
            x: bytes.to_vec().into(),
            d: None,
        }),
        prm: Parameters::default(),
    }
}

fn jwk_to_x25519_bytes(jwk: &Jwk) -> Result<&[u8], CxpError> {
    let Key::Okp(okp) = &jwk.key else {
        return Err(CxpError::UnsupportedHpkeParameters(
            "expected an OKP JWK key for the X25519 HPKE KEM".to_string(),
        ));
    };
    if !matches!(okp.crv, OkpCurves::X25519) {
        return Err(CxpError::UnsupportedHpkeParameters(
            "expected an X25519 OKP curve".to_string(),
        ));
    }
    Ok(okp.x.as_ref())
}

fn private_key_from_bytes(bytes: &[u8]) -> Result<<Kem as KemTrait>::PrivateKey, CxpError> {
    <Kem as KemTrait>::PrivateKey::from_bytes(bytes)
        .map_err(|e| CxpError::DecryptionError(format!("invalid HPKE private key: {e}")))
}

pub(crate) struct SealedMessage {
    pub encapped_key_jwk: Jwk,
    pub ciphertext: Vec<u8>,
}

pub(crate) fn seal(recipient_jwk: &Jwk, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<SealedMessage, CxpError> {
    let recipient_key_bytes = jwk_to_x25519_bytes(recipient_jwk)?;
    let recipient_key = <Kem as KemTrait>::PublicKey::from_bytes(recipient_key_bytes)
        .map_err(|e| CxpError::UnsupportedHpkeParameters(format!("invalid HPKE public key: {e}")))?;
    let (encapped_key, ciphertext) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &recipient_key, info, plaintext, aad)
            .map_err(|e| CxpError::EncryptionError(format!("HPKE seal failed: {e}")))?;
    Ok(SealedMessage {
        encapped_key_jwk: x25519_bytes_to_jwk(&encapped_key.to_bytes()),
        ciphertext,
    })
}

pub(crate) fn open(
    private_key: &[u8],
    encapped_key_jwk: &Jwk,
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CxpError> {
    let private_key = private_key_from_bytes(private_key)?;
    let encapped_key_bytes = jwk_to_x25519_bytes(encapped_key_jwk)?;
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(encapped_key_bytes)
        .map_err(|e| CxpError::DecryptionError(format!("invalid HPKE encapsulated key: {e}")))?;
    hpke::single_shot_open::<Aead, Kdf, Kem>(&OpModeR::Base, &private_key, &encapped_key, info, ciphertext, aad)
        .map(Zeroizing::new)
        .map_err(|e| CxpError::DecryptionError(format!("HPKE open failed: {e}")))
}
