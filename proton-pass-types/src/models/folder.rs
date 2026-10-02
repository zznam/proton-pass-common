/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Proton Pass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

use crate::protos::folder::folder_v1;
use crate::update::update_preserving_unknown;
use anyhow::{Context, Result, anyhow};
use protobuf::Message;

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderData {
    pub name: String,
}

impl FolderData {
    pub fn new(name: String) -> Result<Self> {
        if name.is_empty() {
            return Err(anyhow!("The folder name cannot be empty."));
        }

        Ok(Self { name })
    }

    pub fn serialize(self) -> Result<Vec<u8>> {
        let as_proto = folder_v1::Folder::from(self);
        as_proto.to_vec().context("Error serializing folder to proto")
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let as_proto = folder_v1::Folder::parse_from_bytes(data).context("Error decoding Folder from proto")?;
        Ok(Self::from(as_proto))
    }

    pub fn perform_update(original: &[u8], new: &Self) -> Result<Vec<u8>> {
        update_preserving_unknown(original, &folder_v1::Folder::from(new.clone()))
    }
}

impl From<FolderData> for folder_v1::Folder {
    fn from(value: FolderData) -> Self {
        folder_v1::Folder {
            name: value.name,
            ..Default::default()
        }
    }
}

impl From<folder_v1::Folder> for FolderData {
    fn from(value: folder_v1::Folder) -> Self {
        Self { name: value.name }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serialize_deserialize() {
        let folder = FolderData::new("My folder".to_string()).unwrap();
        let serialized = folder.clone().serialize().unwrap();
        let deserialized = FolderData::deserialize(&serialized).unwrap();
        assert_eq!(folder, deserialized);
    }

    #[test]
    fn new_rejects_empty_name() {
        assert!(FolderData::new(String::new()).is_err());
    }

    #[test]
    fn perform_update_replaces_scalar_field() {
        let original = FolderData::new("Original".to_string()).unwrap();
        let original_bytes = original.serialize().unwrap();

        let updated = FolderData::new("Updated".to_string()).unwrap();
        let updated_bytes = FolderData::perform_update(&original_bytes, &updated).unwrap();

        let result = FolderData::deserialize(&updated_bytes).unwrap();
        assert_eq!(result.name, "Updated");
    }

    #[test]
    fn perform_update_preserves_unknown_field() {
        let original = FolderData::new("Original".to_string()).unwrap();
        let mut original_as_proto = folder_v1::Folder::from(original);
        original_as_proto.mut_unknown_fields().add_fixed64(999, 123456789);
        let original_bytes = original_as_proto.to_vec().unwrap();

        let updated = FolderData::new("Updated".to_string()).unwrap();
        let updated_bytes = FolderData::perform_update(&original_bytes, &updated).unwrap();

        let result_as_proto = folder_v1::Folder::parse_from_bytes(&updated_bytes).unwrap();
        assert_eq!(
            result_as_proto.unknown_fields().get(999),
            Some(protobuf::UnknownValueRef::Fixed64(123456789))
        );
    }
}
