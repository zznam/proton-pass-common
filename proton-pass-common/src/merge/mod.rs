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

#[allow(clippy::module_inception)]
mod merge;
mod plan;

pub use plan::*;

use proton_pass_derive::{Error, ffi_error, ffi_type};
use proton_pass_types::ItemData;

#[ffi_type]
#[derive(Clone, Debug)]
pub struct ItemForMerge {
    pub item_id: String,
    pub share_id: String,
    pub item: ItemData,
}

#[ffi_type]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeActionKind {
    Identical,
    KeepPrimary,
    TakeSecondary,
    ConflictToCustomField,
    Union,
}

#[ffi_type]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeFieldKind {
    Title,
    Note,
    Email,
    Username,
    Password,
    Totp,
    Urls,
    AutofillUrls,
    ExtraField,
    Passkey,
    PlatformSpecific,
    CustomIcon,
    // Credit card content fields.
    CardholderName,
    CardType,
    CardNumber,
    CardVerificationNumber,
    CardExpirationDate,
    CardPin,
    // Identity content fields.
    IdentityFullName,
    IdentityEmail,
    IdentityPhoneNumber,
    IdentityFirstName,
    IdentityMiddleName,
    IdentityLastName,
    IdentityBirthdate,
    IdentityGender,
    IdentitySocialSecurityNumber,
    IdentityPassportNumber,
    IdentityLicenseNumber,
    IdentityOrganization,
    IdentityStreetAddress,
    IdentityZipOrPostalCode,
    IdentityCity,
    IdentityStateOrProvince,
    IdentityCountryOrRegion,
    IdentityFloor,
    IdentityCounty,
    IdentityWebsite,
    IdentityXHandle,
    IdentitySecondPhoneNumber,
    IdentityLinkedin,
    IdentityReddit,
    IdentityFacebook,
    IdentityYahoo,
    IdentityInstagram,
    IdentityCompany,
    IdentityJobTitle,
    IdentityPersonalWebsite,
    IdentityWorkPhoneNumber,
    IdentityWorkEmail,
    // Structured lists inside an item's content (sections and identity detail lists).
    Section,
    // Wifi content fields.
    WifiSsid,
    WifiPassword,
    WifiSecurity,
    // SSH key content fields.
    SshPublicKey,
    SshPrivateKey,
}

#[ffi_type]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeFieldAction {
    pub kind: MergeActionKind,
    pub field: MergeFieldKind,
}

#[ffi_type]
#[derive(Clone, Debug)]
pub struct MergePlan {
    pub primary_id: String,
    pub secondary_id: String,
    pub actions: Vec<MergeFieldAction>,
    pub merged_item: ItemData,
}

#[ffi_type]
#[derive(Clone, Debug)]
pub struct GroupMergePlan {
    pub primary_id: String,
    pub secondary_plans: Vec<MergePlan>,
    pub merged_item: ItemData,
}

#[ffi_error]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MergeError {
    IncompatibleItemTypes(String),
    DuplicateItem(String),
}
