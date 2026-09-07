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

use proton_pass_common::merge::{
    GroupMergePlan, ItemForMerge, MergeError, MergePlan, plan_group_merge, plan_item_merge,
};

#[derive(uniffi::Object)]
pub struct ItemMerger;

#[uniffi::export]
impl ItemMerger {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Plans merging `secondary` into `primary`. The plan carries both the per-field decisions
    /// (for display) and the resulting merged item (for persisting the update).
    pub fn plan_merge(&self, primary: ItemForMerge, secondary: ItemForMerge) -> Result<MergePlan, MergeError> {
        plan_item_merge(&primary, &secondary)
    }

    /// Plans merging a whole group: `secondaries` are folded into `primary` in the given (visual)
    /// order. The result describes one batch update of the primary followed by trashing the
    /// secondaries, which platforms can execute as a single commit.
    pub fn plan_group_merge(
        &self,
        primary: ItemForMerge,
        secondaries: Vec<ItemForMerge>,
    ) -> Result<GroupMergePlan, MergeError> {
        plan_group_merge(&primary, &secondaries)
    }
}
