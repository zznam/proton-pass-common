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

use std::collections::HashSet;
use std::hash::Hash;
use std::mem::take;

use super::{MergeActionKind, MergeFieldAction, MergeFieldKind};
use proton_pass_types::{
    AutofillUrl, AutofillUrlMode, CardType, CreditCardItem, CustomSection, IdentityItem, ItemExtraField,
    ItemExtraFieldContent, LoginItem, PlatformSpecific, WifiSecurity,
};

pub(super) fn action(kind: MergeActionKind, field: MergeFieldKind) -> MergeFieldAction {
    MergeFieldAction { kind, field }
}

pub(super) fn conflict_field(secondary_title: &str, label: &str, content: ItemExtraFieldContent) -> ItemExtraField {
    ItemExtraField {
        name: format!("{secondary_title} - {label}"),
        content,
    }
}

/// Merges one single-valued scalar field (note, email, username, password, TOTP uri, ...):
/// - Same value or empty secondary -> identical.
/// - Empty primary takes the secondary's; otherwise the secondary's is preserved as a custom field.
#[allow(clippy::too_many_arguments)]
pub(super) fn merge_scalar_field(
    primary_value: &mut String,
    secondary_value: &str,
    field: MergeFieldKind,
    label: &str,
    secondary_title: &str,
    conflict_content: fn(String) -> ItemExtraFieldContent,
    actions: &mut Vec<MergeFieldAction>,
    conflict_fields: &mut Vec<ItemExtraField>,
) {
    if *primary_value == secondary_value || secondary_value.is_empty() {
        actions.push(action(MergeActionKind::Identical, field));
    } else if primary_value.is_empty() {
        *primary_value = secondary_value.to_string();
        actions.push(action(MergeActionKind::TakeSecondary, field));
    } else {
        conflict_fields.push(conflict_field(
            secondary_title,
            label,
            conflict_content(secondary_value.to_string()),
        ));
        actions.push(action(MergeActionKind::ConflictToCustomField, field));
    }
}

/// Merges enumerated scalars (card type, wifi security) whose "unset" state is a dedicated
/// `Unspecified` variant instead of an empty string: same rules as scalar fields apply.
#[allow(clippy::too_many_arguments)]
pub(super) fn merge_choice_field<T: Clone + PartialEq>(
    primary: &mut T,
    secondary: &T,
    unspecified: T,
    display: impl Fn(&T) -> String,
    field: MergeFieldKind,
    label: &str,
    secondary_title: &str,
    actions: &mut Vec<MergeFieldAction>,
    conflict_fields: &mut Vec<ItemExtraField>,
) {
    if *primary == *secondary || *secondary == unspecified {
        actions.push(action(MergeActionKind::Identical, field));
    } else if *primary == unspecified {
        *primary = secondary.clone();
        actions.push(action(MergeActionKind::TakeSecondary, field));
    } else {
        conflict_fields.push(conflict_field(
            secondary_title,
            label,
            ItemExtraFieldContent::Hidden(display(secondary)),
        ));
        actions.push(action(MergeActionKind::ConflictToCustomField, field));
    }
}

/// Merges a list of same-shaped scalar fields declared as `struct_field => (kind, label, content)`.
macro_rules! merge_struct_scalars {
    ($primary:expr, $secondary:expr, $secondary_title:expr, $actions:expr, $conflicts:expr, {
        $($field:ident => ($kind:ident, $label:literal, $content:expr)),* $(,)?
    }) => {
        $(
            merge_scalar_field(
                &mut $primary.$field,
                &$secondary.$field,
                MergeFieldKind::$kind,
                $label,
                $secondary_title,
                $content,
                $actions,
                $conflicts,
            );
        )*
    };
}

pub(super) fn merge_login_content(
    login: &mut LoginItem,
    secondary_login: &LoginItem,
    secondary_title: &str,
    actions: &mut Vec<MergeFieldAction>,
    conflict_fields: &mut Vec<ItemExtraField>,
) {
    merge_scalar_field(
        &mut login.email,
        &secondary_login.email,
        MergeFieldKind::Email,
        "Email",
        secondary_title,
        ItemExtraFieldContent::Text,
        actions,
        conflict_fields,
    );
    merge_scalar_field(
        &mut login.username,
        &secondary_login.username,
        MergeFieldKind::Username,
        "Username",
        secondary_title,
        ItemExtraFieldContent::Text,
        actions,
        conflict_fields,
    );
    merge_scalar_field(
        &mut login.password,
        &secondary_login.password,
        MergeFieldKind::Password,
        "Password",
        secondary_title,
        ItemExtraFieldContent::Hidden,
        actions,
        conflict_fields,
    );
    merge_scalar_field(
        &mut login.totp_uri,
        &secondary_login.totp_uri,
        MergeFieldKind::Totp,
        "TOTP",
        secondary_title,
        ItemExtraFieldContent::Totp,
        actions,
        conflict_fields,
    );

    // As on create/update, `autofill_urls` is the canonical field, so both items' legacy `urls`
    // are migrated into it before unioning. Autofill urls that already carry a mode keep it;
    // migrated urls get the default mode. One action entry covers the combined list. The legacy
    // `urls` list stays populated with the union so clients that still read it see no regression.
    let mut merged_autofill_urls = take(&mut login.autofill_urls);
    let mut existing: HashSet<String> = merged_autofill_urls.iter().map(|u| u.url.clone()).collect();

    for url in take(&mut login.urls) {
        if existing.insert(url.clone()) {
            merged_autofill_urls.push(AutofillUrl {
                url,
                mode: AutofillUrlMode::Default,
            });
        }
    }

    let mut added = 0;
    let secondary_candidates = secondary_login
        .autofill_urls
        .iter()
        .map(|u| (&u.url, Some(u.mode)))
        .chain(secondary_login.urls.iter().map(|url| (url, None)));
    for (url, mode) in secondary_candidates {
        if existing.insert(url.clone()) {
            merged_autofill_urls.push(AutofillUrl {
                url: url.clone(),
                mode: mode.unwrap_or(AutofillUrlMode::Default),
            });
            added += 1;
        }
    }

    login.urls = merged_autofill_urls.iter().map(|u| u.url.clone()).collect();
    login.autofill_urls = merged_autofill_urls;
    actions.push(union_action(MergeFieldKind::AutofillUrls, added));

    let (passkeys, added_passkeys) = union_by_key(take(&mut login.passkeys), &secondary_login.passkeys, |p| {
        p.key_id.clone()
    });
    login.passkeys = passkeys;
    actions.push(union_action(MergeFieldKind::Passkey, added_passkeys));
}

/// Unions the secondary's custom fields into `merged`: same name and value collapse, same name
/// with a different value keeps both (the secondary's under a source-named title). Returns the
/// number of plain additions and the names given to the conflicting fields.
pub(super) fn merge_extra_fields(
    merged: &mut Vec<ItemExtraField>,
    secondary: &[ItemExtraField],
    secondary_title: &str,
) -> (usize, Vec<String>) {
    let mut added = 0;
    let mut renamed = Vec::new();

    for field in secondary {
        if merged
            .iter()
            .any(|f| f.name == field.name && f.content == field.content)
        {
            continue;
        }

        if merged.iter().any(|f| f.name == field.name) {
            let renamed_field = conflict_field(secondary_title, &field.name, field.content.clone());
            if !merged
                .iter()
                .any(|f| f.name == renamed_field.name && f.content == renamed_field.content)
            {
                renamed.push(renamed_field.name.clone());
                merged.push(renamed_field);
            }
        } else {
            merged.push(field.clone());
            added += 1;
        }
    }

    (added, renamed)
}

/// Unions the secondary's content sections into the primary's by section name: a new name
/// adds the whole section; a shared name merges the section's fields like custom fields (exact
/// duplicates collapse, name conflicts get a source-and-section-named field inside the
/// section). Returns how many sections and fields the secondary contributed.
pub(super) fn merge_sections(
    primary: &mut Vec<CustomSection>,
    secondary: &[CustomSection],
    secondary_title: &str,
) -> usize {
    let mut added = 0;

    for section in secondary {
        let Some(existing) = primary
            .iter_mut()
            .find(|candidate| candidate.section_name == section.section_name)
        else {
            primary.push(section.clone());
            added += 1 + section.section_fields.len();
            continue;
        };

        for field in &section.section_fields {
            if existing
                .section_fields
                .iter()
                .any(|f| f.name == field.name && f.content == field.content)
            {
                continue;
            }

            let conflicting_name = existing.section_fields.iter().any(|f| f.name == field.name);
            let name = if conflicting_name {
                format!("{secondary_title} - {}.{}", section.section_name, field.name)
            } else {
                field.name.clone()
            };
            let new_field = ItemExtraField {
                name,
                content: field.content.clone(),
            };
            if existing
                .section_fields
                .iter()
                .any(|f| f.name == new_field.name && f.content == new_field.content)
            {
                continue;
            }
            existing.section_fields.push(new_field);
            added += 1;
        }
    }

    added
}

pub(super) fn merge_credit_card_content(
    card: &mut CreditCardItem,
    secondary_card: &CreditCardItem,
    secondary_title: &str,
    actions: &mut Vec<MergeFieldAction>,
    conflict_fields: &mut Vec<ItemExtraField>,
) {
    merge_struct_scalars!(card, secondary_card, secondary_title, actions, conflict_fields, {
        cardholder_name => (CardholderName, "Cardholder name", ItemExtraFieldContent::Text),
        number => (CardNumber, "Number", ItemExtraFieldContent::Hidden),
        verification_number => (CardVerificationNumber, "Verification number", ItemExtraFieldContent::Hidden),
        expiration_date => (CardExpirationDate, "Expiration date", ItemExtraFieldContent::Text),
        pin => (CardPin, "PIN", ItemExtraFieldContent::Hidden),
    });
    merge_choice_field(
        &mut card.card_type,
        &secondary_card.card_type,
        CardType::Unspecified,
        |card| card.to_string(),
        MergeFieldKind::CardType,
        "Card type",
        secondary_title,
        actions,
        conflict_fields,
    );
}

pub(super) fn merge_identity_content(
    identity: &mut IdentityItem,
    secondary: &IdentityItem,
    secondary_title: &str,
    actions: &mut Vec<MergeFieldAction>,
    conflict_fields: &mut Vec<ItemExtraField>,
) {
    merge_struct_scalars!(identity, secondary, secondary_title, actions, conflict_fields, {
        full_name => (IdentityFullName, "Full name", ItemExtraFieldContent::Text),
        email => (IdentityEmail, "Email", ItemExtraFieldContent::Text),
        phone_number => (IdentityPhoneNumber, "Phone number", ItemExtraFieldContent::Text),
        first_name => (IdentityFirstName, "First name", ItemExtraFieldContent::Text),
        middle_name => (IdentityMiddleName, "Middle name", ItemExtraFieldContent::Text),
        last_name => (IdentityLastName, "Last name", ItemExtraFieldContent::Text),
        birthdate => (IdentityBirthdate, "Birthdate", ItemExtraFieldContent::Text),
        gender => (IdentityGender, "Gender", ItemExtraFieldContent::Text),
        social_security_number => (IdentitySocialSecurityNumber, "Social security number", ItemExtraFieldContent::Hidden),
        passport_number => (IdentityPassportNumber, "Passport number", ItemExtraFieldContent::Hidden),
        license_number => (IdentityLicenseNumber, "License number", ItemExtraFieldContent::Hidden),
        organization => (IdentityOrganization, "Organization", ItemExtraFieldContent::Text),
        street_address => (IdentityStreetAddress, "Street address", ItemExtraFieldContent::Text),
        zip_or_postal_code => (IdentityZipOrPostalCode, "Zip or postal code", ItemExtraFieldContent::Text),
        city => (IdentityCity, "City", ItemExtraFieldContent::Text),
        state_or_province => (IdentityStateOrProvince, "State or province", ItemExtraFieldContent::Text),
        country_or_region => (IdentityCountryOrRegion, "Country or region", ItemExtraFieldContent::Text),
        floor => (IdentityFloor, "Floor", ItemExtraFieldContent::Text),
        county => (IdentityCounty, "County", ItemExtraFieldContent::Text),
        website => (IdentityWebsite, "Website", ItemExtraFieldContent::Text),
        x_handle => (IdentityXHandle, "X handle", ItemExtraFieldContent::Text),
        second_phone_number => (IdentitySecondPhoneNumber, "Second phone number", ItemExtraFieldContent::Text),
        linkedin => (IdentityLinkedin, "LinkedIn", ItemExtraFieldContent::Text),
        reddit => (IdentityReddit, "Reddit", ItemExtraFieldContent::Text),
        facebook => (IdentityFacebook, "Facebook", ItemExtraFieldContent::Text),
        yahoo => (IdentityYahoo, "Yahoo", ItemExtraFieldContent::Text),
        instagram => (IdentityInstagram, "Instagram", ItemExtraFieldContent::Text),
        company => (IdentityCompany, "Company", ItemExtraFieldContent::Text),
        job_title => (IdentityJobTitle, "Job title", ItemExtraFieldContent::Text),
        personal_website => (IdentityPersonalWebsite, "Personal website", ItemExtraFieldContent::Text),
        work_phone_number => (IdentityWorkPhoneNumber, "Work phone number", ItemExtraFieldContent::Text),
        work_email => (IdentityWorkEmail, "Work email", ItemExtraFieldContent::Text),
    });

    let mut added = 0;
    for (list, secondary_list) in [
        (&mut identity.extra_personal_details, &secondary.extra_personal_details),
        (&mut identity.extra_address_details, &secondary.extra_address_details),
        (&mut identity.extra_contact_details, &secondary.extra_contact_details),
        (&mut identity.extra_work_details, &secondary.extra_work_details),
    ] {
        let (list_added, renamed) = merge_extra_fields(list, secondary_list, secondary_title);
        added += list_added + renamed.len();
    }
    added += merge_sections(&mut identity.extra_sections, &secondary.extra_sections, secondary_title);
    actions.push(union_action(MergeFieldKind::Section, added));
}

pub(super) fn merge_wifi_content(
    wifi: &mut proton_pass_types::WifiItem,
    secondary: &proton_pass_types::WifiItem,
    secondary_title: &str,
    actions: &mut Vec<MergeFieldAction>,
    conflict_fields: &mut Vec<ItemExtraField>,
) {
    merge_struct_scalars!(wifi, secondary, secondary_title, actions, conflict_fields, {
        ssid => (WifiSsid, "SSID", ItemExtraFieldContent::Text),
        password => (WifiPassword, "Password", ItemExtraFieldContent::Hidden),
    });
    merge_choice_field(
        &mut wifi.security,
        &secondary.security,
        WifiSecurity::UnspecifiedWifiSecurity,
        |security| security.to_string(),
        MergeFieldKind::WifiSecurity,
        "Security",
        secondary_title,
        actions,
        conflict_fields,
    );
    let added = merge_sections(&mut wifi.sections, &secondary.sections, secondary_title);
    actions.push(union_action(MergeFieldKind::Section, added));
}

pub(super) fn merge_ssh_key_content(
    ssh_key: &mut proton_pass_types::SshKeyItem,
    secondary: &proton_pass_types::SshKeyItem,
    secondary_title: &str,
    actions: &mut Vec<MergeFieldAction>,
    conflict_fields: &mut Vec<ItemExtraField>,
) {
    merge_struct_scalars!(ssh_key, secondary, secondary_title, actions, conflict_fields, {
        private_key => (SshPrivateKey, "Private key", ItemExtraFieldContent::Hidden),
        public_key => (SshPublicKey, "Public key", ItemExtraFieldContent::Hidden),
    });
    let added = merge_sections(&mut ssh_key.sections, &secondary.sections, secondary_title);
    actions.push(union_action(MergeFieldKind::Section, added));
}

pub(super) fn extra_fields_action(added: usize, renamed: Vec<String>) -> MergeFieldAction {
    if added == 0 && renamed.is_empty() {
        return action(MergeActionKind::Identical, MergeFieldKind::ExtraField);
    }
    action(MergeActionKind::Union, MergeFieldKind::ExtraField)
}

/// Unions the secondary's Android allowed apps into the primary's, by package name.
pub(super) fn merge_platform_specific(
    primary: &mut Option<PlatformSpecific>,
    secondary: &Option<PlatformSpecific>,
    actions: &mut Vec<MergeFieldAction>,
) {
    let Some(secondary) = secondary else {
        actions.push(action(MergeActionKind::Identical, MergeFieldKind::PlatformSpecific));
        return;
    };

    let Some(primary) = primary else {
        *primary = Some(secondary.clone());
        actions.push(action(MergeActionKind::TakeSecondary, MergeFieldKind::PlatformSpecific));
        return;
    };

    let secondary_android = secondary.android.clone().unwrap_or_default();
    if let Some(primary_android) = &mut primary.android {
        let (allowed_apps, added) = union_by_key(
            take(&mut primary_android.allowed_apps),
            &secondary_android.allowed_apps,
            |app| app.package_name.clone(),
        );
        primary_android.allowed_apps = allowed_apps;
        actions.push(union_action(MergeFieldKind::PlatformSpecific, added));
    } else if !secondary_android.allowed_apps.is_empty() {
        primary.android = Some(secondary_android);
        actions.push(action(MergeActionKind::TakeSecondary, MergeFieldKind::PlatformSpecific));
    } else {
        actions.push(action(MergeActionKind::Identical, MergeFieldKind::PlatformSpecific));
    }
}

/// The icon is single-valued: an empty primary takes the secondary's, otherwise the primary's
/// is kept (the secondary's is recoverable from Trash).
pub(super) fn merge_custom_icon(
    merged: &mut proton_pass_types::ItemData,
    secondary: &proton_pass_types::ItemData,
    actions: &mut Vec<MergeFieldAction>,
) {
    if merged.custom_icon.is_none() && secondary.custom_icon.is_some() {
        merged.custom_icon = secondary.custom_icon.clone();
        actions.push(action(MergeActionKind::TakeSecondary, MergeFieldKind::CustomIcon));
    } else {
        actions.push(action(MergeActionKind::Identical, MergeFieldKind::CustomIcon));
    }
}

/// Ordered union: every item of `acc` (the primary's values) kept in order, then every item of
/// `secondary` whose key hasn't been seen yet, in order. Duplicates within a single item's
/// list collapse too. Returns the union and how many items the secondary contributed.
pub(super) fn union_by_key<T: Clone, K: Hash + Eq>(
    mut acc: Vec<T>,
    secondary: &[T],
    key: impl Fn(&T) -> K,
) -> (Vec<T>, usize) {
    let mut seen: HashSet<K> = acc.iter().map(&key).collect();
    let mut added = 0;

    for item in secondary {
        if seen.insert(key(item)) {
            acc.push(item.clone());
            added += 1;
        }
    }

    (acc, added)
}

pub(super) fn union_action(field: MergeFieldKind, added: usize) -> MergeFieldAction {
    if added == 0 {
        return action(MergeActionKind::Identical, field);
    }
    action(MergeActionKind::Union, field)
}

#[cfg(test)]
mod test {
    use proton_pass_types::{
        AllowedAndroidApp, AndroidSpecific, CardType, CreditCardItem, CustomItem, CustomSection, IdentityItem,
        ItemContent, ItemData, ItemExtraField, ItemExtraFieldContent, ItemExtraFieldContent::*, LoginItem,
        PlatformSpecific, SshKeyItem, WifiItem, WifiSecurity,
    };

    use super::*;
    use crate::merge::MergeActionKind;

    fn extra_field(name: &str, content: ItemExtraFieldContent) -> ItemExtraField {
        ItemExtraField {
            name: name.to_string(),
            content,
        }
    }

    fn section(name: &str, fields: Vec<ItemExtraField>) -> CustomSection {
        CustomSection {
            section_name: name.to_string(),
            section_fields: fields,
        }
    }

    fn actions_and_conflicts() -> (Vec<MergeFieldAction>, Vec<ItemExtraField>) {
        (Vec::new(), Vec::new())
    }

    fn find_action(actions: &[MergeFieldAction], field: MergeFieldKind) -> MergeActionKind {
        actions
            .iter()
            .find(|a| a.field == field)
            .map(|a| a.kind)
            .expect("action should exist")
    }

    mod scalar_field {
        use super::*;

        #[test]
        fn same_value_is_identical() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut value = "same".to_string();

            merge_scalar_field(
                &mut value,
                "same",
                MergeFieldKind::Username,
                "Username",
                "Secondary",
                ItemExtraFieldContent::Text,
                &mut actions,
                &mut conflicts,
            );

            assert_eq!(value, "same");
            assert!(conflicts.is_empty());
            assert_eq!(
                find_action(&actions, MergeFieldKind::Username),
                MergeActionKind::Identical
            );
        }

        #[test]
        fn empty_secondary_is_identical() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut value = "filled".to_string();

            merge_scalar_field(
                &mut value,
                "",
                MergeFieldKind::Username,
                "Username",
                "Secondary",
                ItemExtraFieldContent::Text,
                &mut actions,
                &mut conflicts,
            );

            assert_eq!(value, "filled");
            assert!(conflicts.is_empty());
            assert_eq!(
                find_action(&actions, MergeFieldKind::Username),
                MergeActionKind::Identical
            );
        }

        #[test]
        fn empty_primary_takes_secondary() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut value = String::new();

            merge_scalar_field(
                &mut value,
                "secondary value",
                MergeFieldKind::Username,
                "Username",
                "Secondary",
                ItemExtraFieldContent::Text,
                &mut actions,
                &mut conflicts,
            );

            assert_eq!(value, "secondary value");
            assert!(conflicts.is_empty());
            assert_eq!(
                find_action(&actions, MergeFieldKind::Username),
                MergeActionKind::TakeSecondary
            );
        }

        #[test]
        fn conflict_becomes_source_named_custom_field() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut value = "primary".to_string();

            merge_scalar_field(
                &mut value,
                "secondary",
                MergeFieldKind::Password,
                "Password",
                "Secondary",
                ItemExtraFieldContent::Hidden,
                &mut actions,
                &mut conflicts,
            );

            assert_eq!(value, "primary");
            assert_eq!(
                conflicts,
                vec![extra_field(
                    "Secondary - Password",
                    ItemExtraFieldContent::Hidden("secondary".into())
                )]
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::Password),
                MergeActionKind::ConflictToCustomField
            );
        }
    }

    mod choice_field {
        use super::*;

        #[test]
        fn unspecified_takes_secondary() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut choice = CardType::Unspecified;

            merge_choice_field(
                &mut choice,
                &CardType::Visa,
                CardType::Unspecified,
                |card| card.to_string(),
                MergeFieldKind::CardType,
                "Card type",
                "Secondary",
                &mut actions,
                &mut conflicts,
            );

            assert_eq!(choice, CardType::Visa);
            assert!(conflicts.is_empty());
            assert_eq!(
                find_action(&actions, MergeFieldKind::CardType),
                MergeActionKind::TakeSecondary
            );
        }

        #[test]
        fn conflict_becomes_hidden_custom_field() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut choice = CardType::Visa;

            merge_choice_field(
                &mut choice,
                &CardType::Mastercard,
                CardType::Unspecified,
                |card| card.to_string(),
                MergeFieldKind::CardType,
                "Card type",
                "Secondary",
                &mut actions,
                &mut conflicts,
            );

            assert_eq!(choice, CardType::Visa);
            assert_eq!(
                conflicts,
                vec![extra_field("Secondary - Card type", Hidden("Mastercard".into()))]
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::CardType),
                MergeActionKind::ConflictToCustomField
            );
        }
    }

    mod login_content {
        use super::*;
        use proton_pass_types::{AutofillUrl, AutofillUrlMode};

        fn login(username: &str, password: &str, totp_uri: &str) -> LoginItem {
            LoginItem {
                email: String::new(),
                username: username.to_string(),
                password: password.to_string(),
                urls: vec![],
                totp_uri: totp_uri.to_string(),
                passkeys: vec![],
                autofill_urls: vec![],
            }
        }

        #[test]
        fn scalars_use_matching_custom_field_types() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = login("bob", "pw", "otpauth://totp/primary");
            let mut secondary = login("bobby", "pw2", "otpauth://totp/secondary");
            primary.email = "bob@proton.me".into();
            secondary.email = "bob@gmail.com".into();

            merge_login_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(primary.username, "bob");
            assert_eq!(primary.password, "pw");
            assert_eq!(primary.totp_uri, "otpauth://totp/primary");
            assert_eq!(
                conflicts,
                vec![
                    extra_field("Secondary - Email", Text("bob@gmail.com".into())),
                    extra_field("Secondary - Username", Text("bobby".into())),
                    extra_field("Secondary - Password", Hidden("pw2".into())),
                    extra_field("Secondary - TOTP", Totp("otpauth://totp/secondary".into())),
                ]
            );
        }

        #[test]
        fn urls_are_migrated_into_autofill_urls_and_unioned_primary_first() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = login("", "", "");
            let mut secondary = login("", "", "");
            primary.urls = vec!["https://amazon.com".into(), "https://shop.com".into()];
            secondary.urls = vec!["https://amazon.com".into(), "https://smile.amazon.com".into()];

            merge_login_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(
                primary.urls,
                vec!["https://amazon.com", "https://shop.com", "https://smile.amazon.com"]
            );
            assert_eq!(
                primary.autofill_urls.iter().map(|u| u.url.as_str()).collect::<Vec<_>>(),
                vec!["https://amazon.com", "https://shop.com", "https://smile.amazon.com"]
            );
            assert!(conflicts.is_empty());
            assert_eq!(
                find_action(&actions, MergeFieldKind::AutofillUrls),
                MergeActionKind::Union
            );
        }

        #[test]
        fn urls_and_autofill_urls_are_unioned_into_one_deduplicated_list() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = login("", "", "");
            let mut secondary = login("", "", "");
            primary.urls = vec!["https://legacy.com".into()];
            primary.autofill_urls = vec![AutofillUrl {
                url: "https://autofill.com".into(),
                mode: AutofillUrlMode::Default,
            }];
            secondary.urls = vec!["https://legacy.com".into(), "https://other-legacy.com".into()];
            secondary.autofill_urls = vec![
                AutofillUrl {
                    url: "https://autofill.com".into(),
                    mode: AutofillUrlMode::Default,
                },
                AutofillUrl {
                    url: "https://new.com".into(),
                    mode: AutofillUrlMode::Exact,
                },
            ];

            merge_login_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(
                primary.urls,
                vec![
                    "https://autofill.com",
                    "https://legacy.com",
                    "https://new.com",
                    "https://other-legacy.com"
                ]
            );
            let autofill: Vec<(&str, AutofillUrlMode)> =
                primary.autofill_urls.iter().map(|u| (u.url.as_str(), u.mode)).collect();
            assert_eq!(
                autofill,
                vec![
                    ("https://autofill.com", AutofillUrlMode::Default),
                    ("https://legacy.com", AutofillUrlMode::Default),
                    ("https://new.com", AutofillUrlMode::Exact),
                    ("https://other-legacy.com", AutofillUrlMode::Default),
                ]
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::AutofillUrls),
                MergeActionKind::Union
            );
        }

        #[test]
        fn identical_urls_leave_both_fields_populated_and_autofill_action_identical() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = login("", "", "");
            let mut secondary = login("", "", "");
            primary.urls = vec!["https://amazon.com".into()];
            secondary.urls = vec!["https://amazon.com".into()];

            merge_login_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(primary.urls, vec!["https://amazon.com"]);
            assert_eq!(
                primary.autofill_urls.iter().map(|u| u.url.as_str()).collect::<Vec<_>>(),
                vec!["https://amazon.com"]
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::AutofillUrls),
                MergeActionKind::Identical
            );
            assert!(actions.iter().all(|a| a.field != MergeFieldKind::Urls));
        }
    }

    mod extra_fields {
        use super::*;

        #[test]
        fn same_name_and_value_collapse() {
            let mut merged = vec![extra_field("Router", Text("1.2.3.4".into()))];
            let secondary = vec![extra_field("Router", Text("1.2.3.4".into()))];

            let (added, renamed) = merge_extra_fields(&mut merged, &secondary, "Secondary");

            assert_eq!((added, renamed.len()), (0, 0));
            assert_eq!(merged.len(), 1);
        }

        #[test]
        fn same_name_different_value_keeps_both() {
            let mut merged = vec![extra_field("Router", Text("1.2.3.4".into()))];
            let secondary = vec![extra_field("Router", Text("5.6.7.8".into()))];

            let (added, renamed) = merge_extra_fields(&mut merged, &secondary, "Secondary");

            assert_eq!((added, renamed.len()), (0, 1));
            assert_eq!(
                merged,
                vec![
                    extra_field("Router", Text("1.2.3.4".into())),
                    extra_field("Secondary - Router", Text("5.6.7.8".into())),
                ]
            );
        }

        #[test]
        fn disjoint_names_are_all_kept() {
            let mut merged = vec![extra_field("Router", Text("1.2.3.4".into()))];
            let secondary = vec![
                extra_field("Router", Text("1.2.3.4".into())),
                extra_field("Channel", Hidden("6".into())),
            ];

            let (added, renamed) = merge_extra_fields(&mut merged, &secondary, "Secondary");

            assert_eq!((added, renamed.len()), (1, 0));
            assert_eq!(
                merged,
                vec![
                    extra_field("Router", Text("1.2.3.4".into())),
                    extra_field("Channel", Hidden("6".into())),
                ]
            );
        }
    }

    mod sections {
        use super::*;

        #[test]
        fn new_names_add_whole_section() {
            let mut primary = vec![section("main", vec![extra_field("A", Text("1".into()))])];
            let secondary = vec![section("other", vec![extra_field("B", Text("2".into()))])];

            let added = merge_sections(&mut primary, &secondary, "Secondary");

            assert_eq!(added, 2);
            assert_eq!(primary.len(), 2);
            assert_eq!(primary[1].section_name, "other");
        }

        #[test]
        fn same_name_merges_fields_collapsing_duplicates() {
            let mut primary = vec![section("s", vec![extra_field("Number", Text("1111".into()))])];
            let secondary = vec![section(
                "s",
                vec![
                    extra_field("Number", Text("1111".into())),
                    extra_field("CVV", Hidden("123".into())),
                ],
            )];

            let added = merge_sections(&mut primary, &secondary, "Secondary");

            assert_eq!(added, 1);
            assert_eq!(
                primary[0].section_fields,
                vec![
                    extra_field("Number", Text("1111".into())),
                    extra_field("CVV", Hidden("123".into())),
                ]
            );
        }

        #[test]
        fn conflicting_field_values_are_source_named() {
            let mut primary = vec![section("s", vec![extra_field("Number", Text("1111".into()))])];
            let secondary = vec![section("s", vec![extra_field("Number", Text("2222".into()))])];

            merge_sections(&mut primary, &secondary, "Secondary");

            assert_eq!(
                primary[0].section_fields,
                vec![
                    extra_field("Number", Text("1111".into())),
                    extra_field("Secondary - s.Number", Text("2222".into())),
                ]
            );
        }
    }

    mod credit_card {
        use super::*;

        fn card(number: &str, pin: &str, card_type: CardType) -> CreditCardItem {
            CreditCardItem {
                cardholder_name: "Bob".into(),
                card_type,
                number: number.into(),
                verification_number: "123".into(),
                expiration_date: "12/28".into(),
                pin: pin.into(),
            }
        }

        #[test]
        fn fields_are_merged_individually() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = card("4242", "1234", CardType::Visa);
            let secondary = card("1111", "9999", CardType::Visa);

            merge_credit_card_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(primary.number, "4242");
            assert_eq!(primary.pin, "1234");
            assert_eq!(
                conflicts,
                vec![
                    extra_field("Secondary - Number", Hidden("1111".into())),
                    extra_field("Secondary - PIN", Hidden("9999".into())),
                ]
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::CardNumber),
                MergeActionKind::ConflictToCustomField
            );
        }

        #[test]
        fn empty_field_is_filled_from_secondary() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = card("", "", CardType::Unspecified);
            let secondary = card("1111", "", CardType::Mastercard);

            merge_credit_card_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(primary.number, "1111");
            assert_eq!(primary.card_type, CardType::Mastercard);
            assert!(conflicts.is_empty());
            assert_eq!(
                find_action(&actions, MergeFieldKind::CardNumber),
                MergeActionKind::TakeSecondary
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::CardType),
                MergeActionKind::TakeSecondary
            );
        }
    }

    mod identity {
        use super::*;

        fn identity() -> IdentityItem {
            IdentityItem {
                full_name: String::new(),
                email: String::new(),
                phone_number: String::new(),
                first_name: String::new(),
                middle_name: String::new(),
                last_name: String::new(),
                birthdate: String::new(),
                gender: String::new(),
                extra_personal_details: vec![],
                organization: String::new(),
                street_address: String::new(),
                zip_or_postal_code: String::new(),
                city: String::new(),
                state_or_province: String::new(),
                country_or_region: String::new(),
                floor: String::new(),
                county: String::new(),
                extra_address_details: vec![],
                social_security_number: String::new(),
                passport_number: String::new(),
                license_number: String::new(),
                website: String::new(),
                x_handle: String::new(),
                second_phone_number: String::new(),
                linkedin: String::new(),
                reddit: String::new(),
                facebook: String::new(),
                yahoo: String::new(),
                instagram: String::new(),
                extra_contact_details: vec![],
                company: String::new(),
                job_title: String::new(),
                personal_website: String::new(),
                work_phone_number: String::new(),
                work_email: String::new(),
                extra_work_details: vec![],
                extra_sections: vec![],
            }
        }

        #[test]
        fn fields_are_merged_individually_with_sensitive_fields_hidden() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = identity();
            primary.full_name = "Bob Builder".into();
            primary.social_security_number = "111-11-1111".into();
            let mut secondary = identity();
            secondary.full_name = "Robert Builder".into();
            secondary.social_security_number = "999-99-9999".into();

            merge_identity_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(primary.full_name, "Bob Builder");
            assert_eq!(primary.social_security_number, "111-11-1111");
            assert_eq!(
                conflicts,
                vec![
                    extra_field("Secondary - Full name", Text("Robert Builder".into())),
                    extra_field("Secondary - Social security number", Hidden("999-99-9999".into())),
                ]
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::IdentityFullName),
                MergeActionKind::ConflictToCustomField
            );
            assert_eq!(
                find_action(&actions, MergeFieldKind::IdentityEmail),
                MergeActionKind::Identical
            );
        }

        #[test]
        fn extra_detail_lists_and_sections_are_unioned() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = identity();
            primary.extra_personal_details = vec![extra_field("Nickname", Text("Bob".into()))];
            primary.extra_sections = vec![section("docs", vec![extra_field("License", Hidden("D1".into()))])];
            let mut secondary = identity();
            secondary.extra_personal_details = vec![
                extra_field("Nickname", Text("Bob".into())),
                extra_field("Maiden name", Text("Smith".into())),
            ];
            secondary.extra_sections = vec![section("docs", vec![extra_field("Passport", Hidden("P2".into()))])];

            merge_identity_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(
                primary.extra_personal_details,
                vec![
                    extra_field("Nickname", Text("Bob".into())),
                    extra_field("Maiden name", Text("Smith".into())),
                ]
            );
            assert_eq!(
                primary.extra_sections,
                vec![section(
                    "docs",
                    vec![
                        extra_field("License", Hidden("D1".into())),
                        extra_field("Passport", Hidden("P2".into())),
                    ]
                )]
            );
            assert_eq!(find_action(&actions, MergeFieldKind::Section), MergeActionKind::Union);
        }
    }

    mod wifi {
        use super::*;

        fn wifi(ssid: &str, password: &str, security: WifiSecurity) -> WifiItem {
            WifiItem {
                ssid: ssid.into(),
                password: password.into(),
                security,
                sections: vec![],
            }
        }

        #[test]
        fn fields_are_merged_individually() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = wifi("MyWifi", "pw1", WifiSecurity::WPA2);
            let secondary = wifi("MyWifi", "pw2", WifiSecurity::WPA3);

            merge_wifi_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(primary.ssid, "MyWifi");
            assert_eq!(primary.password, "pw1");
            assert_eq!(primary.security, WifiSecurity::WPA2);
            assert_eq!(
                conflicts,
                vec![
                    extra_field("Secondary - Password", Hidden("pw2".into())),
                    extra_field("Secondary - Security", Hidden("WPA3".into())),
                ]
            );
        }

        #[test]
        fn sections_are_unioned() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = wifi("MyWifi", "pw1", WifiSecurity::WPA2);
            primary.sections = vec![section("notes", vec![extra_field("Where", Text("kitchen".into()))])];
            let mut secondary = wifi("", "", WifiSecurity::UnspecifiedWifiSecurity);
            secondary.sections = vec![section("notes", vec![extra_field("Where", Text("garage".into()))])];

            merge_wifi_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(
                primary.sections[0].section_fields,
                vec![
                    extra_field("Where", Text("kitchen".into())),
                    extra_field("Secondary - notes.Where", Text("garage".into())),
                ]
            );
            assert_eq!(find_action(&actions, MergeFieldKind::Section), MergeActionKind::Union);
        }
    }

    mod ssh_key {
        use super::*;

        #[test]
        fn fields_are_merged_individually() {
            let (mut actions, mut conflicts) = actions_and_conflicts();
            let mut primary = SshKeyItem {
                private_key: "private-1".into(),
                public_key: "public-1".into(),
                sections: vec![],
            };
            let secondary = SshKeyItem {
                private_key: "private-2".into(),
                public_key: "public-1".into(),
                sections: vec![],
            };

            merge_ssh_key_content(&mut primary, &secondary, "Secondary", &mut actions, &mut conflicts);

            assert_eq!(primary.private_key, "private-1");
            assert_eq!(primary.public_key, "public-1");
            assert_eq!(
                conflicts,
                vec![extra_field("Secondary - Private key", Hidden("private-2".into()))]
            );
        }
    }

    mod platform_specific {
        use super::*;

        fn android_app(package: &str) -> Option<PlatformSpecific> {
            Some(PlatformSpecific {
                android: Some(AndroidSpecific {
                    allowed_apps: vec![AllowedAndroidApp {
                        package_name: package.to_string(),
                        hashes: vec![],
                        app_name: package.to_string(),
                    }],
                }),
            })
        }

        #[test]
        fn allowed_apps_are_unioned_by_package_name() {
            let mut primary = android_app("com.a");
            let secondary = android_app("com.b");

            let mut actions = Vec::new();
            merge_platform_specific(&mut primary, &secondary, &mut actions);

            let apps: Vec<&str> = primary
                .as_ref()
                .and_then(|p| p.android.as_ref())
                .map(|a| a.allowed_apps.iter().map(|app| app.package_name.as_str()).collect())
                .unwrap_or_default();
            assert_eq!(apps, vec!["com.a", "com.b"]);
            assert_eq!(
                find_action(&actions, MergeFieldKind::PlatformSpecific),
                MergeActionKind::Union
            );
        }
    }

    mod custom_icon {
        use super::*;

        fn item_with_icon(icon: Option<Vec<u8>>) -> ItemData {
            let mut item = ItemData::new(
                "Title".into(),
                String::new(),
                "uuid".into(),
                ItemContent::Custom(CustomItem { sections: vec![] }),
                vec![],
            )
            .unwrap();
            item.custom_icon = icon;
            item
        }

        #[test]
        fn empty_primary_takes_secondary() {
            let mut merged = item_with_icon(None);
            let secondary = item_with_icon(Some(vec![1, 2, 3]));

            let mut actions = Vec::new();
            merge_custom_icon(&mut merged, &secondary, &mut actions);

            assert_eq!(merged.custom_icon, Some(vec![1, 2, 3]));
            assert_eq!(
                find_action(&actions, MergeFieldKind::CustomIcon),
                MergeActionKind::TakeSecondary
            );
        }

        #[test]
        fn present_primary_is_kept() {
            let mut merged = item_with_icon(Some(vec![1]));
            let secondary = item_with_icon(Some(vec![2]));

            let mut actions = Vec::new();
            merge_custom_icon(&mut merged, &secondary, &mut actions);

            assert_eq!(merged.custom_icon, Some(vec![1]));
            assert_eq!(
                find_action(&actions, MergeFieldKind::CustomIcon),
                MergeActionKind::Identical
            );
        }
    }

    mod union_by_key {
        use super::*;

        #[test]
        fn keeps_primary_order_and_dedupes() {
            let (union, added) = union_by_key(vec!["a", "b"], &["b", "c", "a"], |x| *x);

            assert_eq!(union, vec!["a", "b", "c"]);
            assert_eq!(added, 1);
        }
    }
}
