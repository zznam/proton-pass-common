use proton_pass_types::{FolderData, ItemAttachmentContent, ItemData, VaultData};

#[derive(Debug, proton_pass_derive::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ProtoSerializationError {
    SerializationError(String),
}

impl From<anyhow::Error> for ProtoSerializationError {
    fn from(e: anyhow::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

#[derive(uniffi::Object)]
pub struct ProtonPassSerialization;

#[uniffi::export]
impl ProtonPassSerialization {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn item_data_serialize(&self, item: ItemData) -> Result<Vec<u8>, ProtoSerializationError> {
        Ok(item.serialize()?)
    }

    pub fn item_data_deserialize(&self, data: Vec<u8>) -> Result<ItemData, ProtoSerializationError> {
        Ok(ItemData::deserialize(&data)?)
    }

    pub fn item_data_perform_update(
        &self,
        original: Vec<u8>,
        updated: ItemData,
    ) -> Result<Vec<u8>, ProtoSerializationError> {
        Ok(ItemData::perform_update(&original, &updated)?)
    }

    pub fn vault_data_serialize(&self, vault: VaultData) -> Result<Vec<u8>, ProtoSerializationError> {
        Ok(vault.serialize()?)
    }

    pub fn vault_data_deserialize(&self, data: Vec<u8>) -> Result<VaultData, ProtoSerializationError> {
        Ok(VaultData::deserialize(&data)?)
    }

    pub fn vault_data_perform_update(
        &self,
        original: Vec<u8>,
        updated: VaultData,
    ) -> Result<Vec<u8>, ProtoSerializationError> {
        Ok(VaultData::perform_update(&original, &updated)?)
    }

    pub fn folder_data_serialize(&self, folder: FolderData) -> Result<Vec<u8>, ProtoSerializationError> {
        Ok(folder.serialize()?)
    }

    pub fn folder_data_deserialize(&self, data: Vec<u8>) -> Result<FolderData, ProtoSerializationError> {
        Ok(FolderData::deserialize(&data)?)
    }

    pub fn folder_data_perform_update(
        &self,
        original: Vec<u8>,
        updated: FolderData,
    ) -> Result<Vec<u8>, ProtoSerializationError> {
        Ok(FolderData::perform_update(&original, &updated)?)
    }

    pub fn item_attachment_content_serialize(
        &self,
        content: ItemAttachmentContent,
    ) -> Result<Vec<u8>, ProtoSerializationError> {
        Ok(content.serialize()?)
    }

    pub fn item_attachment_content_deserialize(
        &self,
        data: Vec<u8>,
    ) -> Result<ItemAttachmentContent, ProtoSerializationError> {
        Ok(ItemAttachmentContent::deserialize(&data)?)
    }
}
