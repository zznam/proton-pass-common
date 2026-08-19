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

use proton_pass_derive::ffi_id_type;

#[ffi_id_type]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ItemId(pub(crate) String);
display_for_basic!(ItemId);

impl ItemId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

#[ffi_id_type]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShareId(pub(crate) String);
display_for_basic!(ShareId);

impl ShareId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

#[ffi_id_type]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VaultId(pub(crate) String);
display_for_basic!(VaultId);

impl VaultId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

#[ffi_id_type]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FolderId(pub(crate) String);
display_for_basic!(FolderId);

impl FolderId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}
