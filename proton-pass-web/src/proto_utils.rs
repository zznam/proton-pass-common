use proton_pass_types::{
    FolderData, FolderDataParseResult, ItemAttachmentContent, ItemAttachmentContentParseResult, ItemData,
    ItemDataParseResult, VaultData, VaultDataParseResult,
};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn item_data_serialize(item: Ts<ItemData>) -> Result<Vec<u8>, JsError> {
    let item = item.to_rust()?;
    item.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn item_data_deserialize(data: Vec<u8>) -> Result<Ts<ItemData>, JsError> {
    let item = ItemData::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(item.into_ts()?)
}

#[wasm_bindgen]
pub fn item_data_perform_update(original: Vec<u8>, updated: Ts<ItemData>) -> Result<Vec<u8>, JsError> {
    let updated = updated.to_rust()?;
    ItemData::perform_update(&original, &updated).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn vault_data_serialize(vault: Ts<VaultData>) -> Result<Vec<u8>, JsError> {
    let vault = vault.to_rust()?;
    vault.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn vault_data_deserialize(data: Vec<u8>) -> Result<Ts<VaultData>, JsError> {
    let vault = VaultData::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(vault.into_ts()?)
}

#[wasm_bindgen]
pub fn vault_data_perform_update(original: Vec<u8>, updated: Ts<VaultData>) -> Result<Vec<u8>, JsError> {
    let updated = updated.to_rust()?;
    VaultData::perform_update(&original, &updated).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn folder_data_serialize(folder: Ts<FolderData>) -> Result<Vec<u8>, JsError> {
    let folder = folder.to_rust()?;
    folder.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn folder_data_deserialize(data: Vec<u8>) -> Result<Ts<FolderData>, JsError> {
    let folder = FolderData::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(folder.into_ts()?)
}

#[wasm_bindgen]
pub fn folder_data_perform_update(original: Vec<u8>, updated: Ts<FolderData>) -> Result<Vec<u8>, JsError> {
    let updated = updated.to_rust()?;
    FolderData::perform_update(&original, &updated).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn item_attachment_content_serialize(content: Ts<ItemAttachmentContent>) -> Result<Vec<u8>, JsError> {
    let content = content.to_rust()?;
    content.serialize().map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn item_attachment_content_deserialize(data: Vec<u8>) -> Result<Ts<ItemAttachmentContent>, JsError> {
    let content = ItemAttachmentContent::deserialize(&data).map_err(|e| JsError::new(&format!("{:?}", e)))?;
    Ok(content.into_ts()?)
}

#[wasm_bindgen]
pub fn item_data_deserialize_many(data: Vec<js_sys::Uint8Array>) -> Result<Ts<ItemDataParseResult>, JsError> {
    let data: Vec<Vec<u8>> = data.iter().map(|d| d.to_vec()).collect();
    Ok(ItemDataParseResult::deserialize_many(&data).into_ts()?)
}

#[wasm_bindgen]
pub fn vault_data_deserialize_many(data: Vec<js_sys::Uint8Array>) -> Result<Ts<VaultDataParseResult>, JsError> {
    let data: Vec<Vec<u8>> = data.iter().map(|d| d.to_vec()).collect();
    Ok(VaultDataParseResult::deserialize_many(&data).into_ts()?)
}

#[wasm_bindgen]
pub fn folder_data_deserialize_many(data: Vec<js_sys::Uint8Array>) -> Result<Ts<FolderDataParseResult>, JsError> {
    let data: Vec<Vec<u8>> = data.iter().map(|d| d.to_vec()).collect();
    Ok(FolderDataParseResult::deserialize_many(&data).into_ts()?)
}

#[wasm_bindgen]
pub fn item_attachment_content_deserialize_many(
    data: Vec<js_sys::Uint8Array>,
) -> Result<Ts<ItemAttachmentContentParseResult>, JsError> {
    let data: Vec<Vec<u8>> = data.iter().map(|d| d.to_vec()).collect();
    Ok(ItemAttachmentContentParseResult::deserialize_many(&data).into_ts()?)
}
