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

use crate::{FolderData, ItemAttachmentContent, ItemData, VaultData};

/// A failure to parse one entry of a batch. `index` is the position of the entry in the input list.
#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub index: u32,
    pub error: String,
}

macro_rules! parse_result {
    ($result:ident, $data:ty) => {
        /// Result of deserializing a list of byte arrays. Successes keep the input order
        /// (skipping failed entries); failures are reported with their input index.
        #[proton_pass_derive::ffi_type]
        #[derive(Clone, Debug)]
        pub struct $result {
            pub successes: Vec<$data>,
            pub errors: Vec<ParseError>,
        }

        impl $result {
            pub fn deserialize_many<T: AsRef<[u8]>>(items: &[T]) -> Self {
                let mut successes = Vec::with_capacity(items.len());
                let mut errors = Vec::new();
                for (index, item) in items.iter().enumerate() {
                    match <$data>::deserialize(item.as_ref()) {
                        Ok(parsed) => successes.push(parsed),
                        Err(e) => errors.push(ParseError {
                            index: index as u32,
                            error: format!("{:?}", e),
                        }),
                    }
                }
                Self { successes, errors }
            }
        }
    };
}

parse_result!(ItemDataParseResult, ItemData);
parse_result!(VaultDataParseResult, VaultData);
parse_result!(FolderDataParseResult, FolderData);
parse_result!(ItemAttachmentContentParseResult, ItemAttachmentContent);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_failures_with_index() {
        let good = FolderData::new("Folder".to_string()).unwrap().serialize().unwrap();
        let bad = vec![0xff, 0xff, 0xff];
        let result = FolderDataParseResult::deserialize_many(&[good.clone(), bad, good]);
        assert_eq!(result.successes.len(), 2);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].index, 1);
        assert!(!result.errors[0].error.is_empty());
    }

    #[test]
    fn empty_input() {
        let result = ItemDataParseResult::deserialize_many::<Vec<u8>>(&[]);
        assert!(result.successes.is_empty());
        assert!(result.errors.is_empty());
    }
}
