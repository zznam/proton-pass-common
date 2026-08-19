use proton_pass_types::{FolderData, ItemAttachmentContent, ItemData, VaultData};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn item_data_serialize(item: ItemData) -> Result<Vec<u8>, JsError> {
    item.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn item_data_deserialize(data: Vec<u8>) -> Result<ItemData, JsError> {
    ItemData::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn item_data_perform_update(original: Vec<u8>, updated: ItemData) -> Result<Vec<u8>, JsError> {
    ItemData::perform_update(&original, &updated).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn vault_data_serialize(vault: VaultData) -> Result<Vec<u8>, JsError> {
    vault.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn vault_data_deserialize(data: Vec<u8>) -> Result<VaultData, JsError> {
    VaultData::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn vault_data_perform_update(original: Vec<u8>, updated: VaultData) -> Result<Vec<u8>, JsError> {
    VaultData::perform_update(&original, &updated).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn folder_data_serialize(folder: FolderData) -> Result<Vec<u8>, JsError> {
    folder.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn folder_data_deserialize(data: Vec<u8>) -> Result<FolderData, JsError> {
    FolderData::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn folder_data_perform_update(original: Vec<u8>, updated: FolderData) -> Result<Vec<u8>, JsError> {
    FolderData::perform_update(&original, &updated).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn item_attachment_content_serialize(content: ItemAttachmentContent) -> Result<Vec<u8>, JsError> {
    content.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn item_attachment_content_deserialize(data: Vec<u8>) -> Result<ItemAttachmentContent, JsError> {
    ItemAttachmentContent::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))
}
