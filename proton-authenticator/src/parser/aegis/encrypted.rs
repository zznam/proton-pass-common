use super::AegisImportError;
use crate::parser::aegis::db::AegisDbRoot;
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::Engine;
use scrypt::{Params as ScryptParams, scrypt};

#[derive(Clone, Debug, serde::Deserialize)]
pub struct KeyParams {
    nonce: String,
    tag: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Slot {
    key: String,
    key_params: KeyParams,
    n: u32,
    r: u32,
    p: u32,
    salt: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct HeaderParams {
    nonce: String,
    tag: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Header {
    slots: Vec<Slot>,
    params: HeaderParams,
}

#[derive(Debug, serde::Deserialize)]
pub struct ExportData {
    header: Header,
    db: String,
}

pub fn decrypt_aegis_encrypted_backup(input: &str, password: &str) -> Result<AegisDbRoot, AegisImportError> {
    let export_data: ExportData = serde_json::from_str(input).map_err(|e| {
        warn!("Error decoding aegis encrypted backup JSON: {e:?}");
        AegisImportError::BadContent
    })?;
    let slot = &export_data.header.slots[0];

    // Convert hex salt string to bytes:
    let salt_bytes = hex::decode(&slot.salt).map_err(|e| {
        warn!("Error decoding aegis encrypted backup salt: {e:?}");
        AegisImportError::BadContent
    })?;

    // Build ScryptParams from the provided N, r, p
    let params = ScryptParams::new(slot.n.trailing_zeros() as u8, slot.r, slot.p).map_err(|e| {
        warn!("Error creating aegis encrypted backup params: {e:?}");
        AegisImportError::UnableToDecrypt
    })?;

    // Our derived key length should be 32 bytes for AES-256.
    let mut derived_key = [0u8; 32];
    scrypt(password.as_bytes(), &salt_bytes, &params, &mut derived_key).map_err(|e| {
        warn!("Error creating scrypt key: {e:?}");
        AegisImportError::BadPassword
    })?;

    let encrypted_master_key = hex::decode(&slot.key).map_err(|e| {
        warn!("Error decoding aegis encrypted backup key: {e:?}");
        AegisImportError::BadContent
    })?;

    // Convert nonce & tag to bytes
    let slot_nonce_bytes = hex::decode(&slot.key_params.nonce).map_err(|e| {
        warn!("Error decoding aegis encrypted backup slot nonce: {e:?}");
        AegisImportError::BadContent
    })?;
    let slot_tag_bytes = hex::decode(&slot.key_params.tag).map_err(|e| {
        warn!("Error decoding aegis encrypted backup tag: {e:?}");
        AegisImportError::BadContent
    })?;

    // Nonce must typically be 12 bytes for GCM:
    let slot_nonce = Nonce::try_from(slot_nonce_bytes.as_slice()).map_err(|e| {
        warn!("Error decoding aegis encrypted backup slot nonce: {e:?}");
        AegisImportError::BadContent
    })?;

    // Tag must be 16 bytes:
    let slot_tag = Tag::try_from(slot_tag_bytes.as_slice()).map_err(|e| {
        warn!("Error decoding aegis encrypted backup tag: {e:?}");
        AegisImportError::BadContent
    })?;

    // Create the AES-256-GCM instance from the derived key
    let cipher = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| {
        warn!("Error creating aegis encrypted backup cipher: {e:?}");
        AegisImportError::UnableToDecrypt
    })?;

    // Copy encrypted bytes into a buffer we can decrypt in place
    let mut master_key_ciphertext = encrypted_master_key.clone();

    // Decrypt in place, providing the tag separately
    cipher
        .decrypt_inout_detached(
            &slot_nonce,
            // optional associated data:
            b"",
            master_key_ciphertext.as_mut_slice().into(),
            &slot_tag,
        )
        .map_err(|e| {
            warn!("Error decrypting aegis encrypted backup: {e:?}");
            AegisImportError::BadPassword
        })?;

    // 5.1 Decode base64 ciphertext
    let db_ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&export_data.db)
        .map_err(|e| {
            warn!("Error decoding encrypted backup DB: {e:?}");
            AegisImportError::BadContent
        })?;

    // 5.2 Decode the JSON's db nonce & tag from hex
    let db_nonce_bytes = hex::decode(&export_data.header.params.nonce).map_err(|e| {
        warn!("Error decoding encrypted backup nonce: {e:?}");
        AegisImportError::BadContent
    })?;
    let db_tag_bytes = hex::decode(&export_data.header.params.tag).map_err(|e| {
        warn!("Error decoding encrypted backup tag: {e:?}");
        AegisImportError::BadContent
    })?;

    // Convert to AES-GCM types
    let db_nonce = Nonce::try_from(db_nonce_bytes.as_slice()).map_err(|e| {
        warn!("Error decoding encrypted backup nonce: {e:?}");
        AegisImportError::BadContent
    })?;
    let db_tag = Tag::try_from(db_tag_bytes.as_slice()).map_err(|e| {
        warn!("Error decoding encrypted backup tag: {e:?}");
        AegisImportError::BadContent
    })?;

    // 5.3 Create a new AES-256-GCM instance, but this time with the decrypted “master key”:
    let master_key = &master_key_ciphertext; // from step 4
    let db_cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| {
        warn!("Error creating encrypted backup DB cipher: {e:?}");
        AegisImportError::UnableToDecrypt
    })?;

    // Copy the ciphertext to a mutable buffer for in-place decryption
    let mut db_ciphertext_mut = db_ciphertext.clone();

    db_cipher
        .decrypt_inout_detached(
            &db_nonce,
            b"", // no additional authenticated data
            db_ciphertext_mut.as_mut_slice().into(),
            &db_tag,
        )
        .map_err(|e| {
            warn!("Error decrypting aegis encrypted backup: {e:?}");
            AegisImportError::UnableToDecrypt
        })?;

    let as_str = String::from_utf8_lossy(&db_ciphertext_mut);

    let parsed: AegisDbRoot = serde_json::from_str(&as_str).map_err(|e| {
        warn!("Error parsing encrypted backup DB: {e:?}");
        AegisImportError::BadContent
    })?;
    Ok(parsed)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_file_contents;

    #[test]
    fn invalid_key_returns_error() {
        let input = get_file_contents("aegis/aegis-json-encrypted-test.json");
        match decrypt_aegis_encrypted_backup(&input, "invalid") {
            Ok(_) => panic!("should not be able to decrypt"),
            Err(AegisImportError::BadPassword) => {} // Expected
            Err(other) => panic!("Expected BadPassword, got {:?}", other),
        }
    }
}
