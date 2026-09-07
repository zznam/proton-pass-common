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

use std::mem::discriminant;

use proton_pass_types::{ItemContent, ItemExtraField, ItemExtraFieldContent};

use super::merge::{
    action, extra_fields_action, merge_credit_card_content, merge_custom_icon, merge_extra_fields,
    merge_identity_content, merge_login_content, merge_platform_specific, merge_scalar_field, merge_sections,
    merge_ssh_key_content, merge_wifi_content, union_action,
};
use super::{GroupMergePlan, ItemForMerge, MergeActionKind, MergeError, MergeFieldKind, MergePlan};

pub fn plan_item_merge(primary: &ItemForMerge, secondary: &ItemForMerge) -> Result<MergePlan, MergeError> {
    if discriminant(&primary.item.content) != discriminant(&secondary.item.content) {
        return Err(MergeError::IncompatibleItemTypes(format!(
            "Cannot merge a {} item into a {} item.",
            secondary.item.content.content_kind(),
            primary.item.content.content_kind()
        )));
    }

    let secondary_title = secondary.item.title.clone();
    let mut merged = primary.item.clone();
    let mut actions = Vec::new();
    let mut conflict_fields = Vec::new();

    // The title is always the primary's.
    if merged.title == secondary.item.title {
        actions.push(action(MergeActionKind::Identical, MergeFieldKind::Title));
    } else {
        actions.push(action(MergeActionKind::KeepPrimary, MergeFieldKind::Title));
    }

    merge_scalar_field(
        &mut merged.note,
        &secondary.item.note,
        MergeFieldKind::Note,
        "Note",
        &secondary_title,
        ItemExtraFieldContent::Text,
        &mut actions,
        &mut conflict_fields,
    );

    // The discriminant check above guarantees the same variant on both sides.
    match (&mut merged.content, &secondary.item.content) {
        (ItemContent::Login(login), ItemContent::Login(secondary_login)) => {
            merge_login_content(
                login,
                secondary_login,
                &secondary_title,
                &mut actions,
                &mut conflict_fields,
            );
        }
        (ItemContent::CreditCard(card), ItemContent::CreditCard(secondary_card)) => {
            merge_credit_card_content(
                card,
                secondary_card,
                &secondary_title,
                &mut actions,
                &mut conflict_fields,
            );
        }
        (ItemContent::Identity(identity), ItemContent::Identity(secondary_identity)) => {
            merge_identity_content(
                identity,
                secondary_identity,
                &secondary_title,
                &mut actions,
                &mut conflict_fields,
            );
        }
        (ItemContent::Wifi(wifi), ItemContent::Wifi(secondary_wifi)) => {
            merge_wifi_content(
                wifi,
                secondary_wifi,
                &secondary_title,
                &mut actions,
                &mut conflict_fields,
            );
        }
        (ItemContent::SshKey(ssh_key), ItemContent::SshKey(secondary_ssh_key)) => {
            merge_ssh_key_content(
                ssh_key,
                secondary_ssh_key,
                &secondary_title,
                &mut actions,
                &mut conflict_fields,
            );
        }
        (ItemContent::Custom(custom), ItemContent::Custom(secondary_custom)) => {
            let added = merge_sections(&mut custom.sections, &secondary_custom.sections, &secondary_title);
            actions.push(union_action(MergeFieldKind::Section, added));
        }
        // Note and alias items have no content beyond title and note, and cross-type merges
        // were rejected above, so nothing else can reach this arm.
        _ => {}
    }

    let (added_fields, renamed_fields) =
        merge_extra_fields(&mut merged.extra_fields, &secondary.item.extra_fields, &secondary_title);
    actions.push(extra_fields_action(added_fields, renamed_fields));

    merge_platform_specific(
        &mut merged.platform_specific,
        &secondary.item.platform_specific,
        &mut actions,
    );
    merge_custom_icon(&mut merged, &secondary.item, &mut actions);

    // Conflict custom fields go last, after the union, so they can never be shadowed by a field
    // inherited from the secondary item. Repeated folds can emit identical conflict fields (same
    // source title and value), so collapse exact duplicates and rename any remaining collisions
    // with a numbered suffix instead of appending blindly.
    for field in conflict_fields {
        if merged
            .extra_fields
            .iter()
            .any(|f| f.name == field.name && f.content == field.content)
        {
            continue;
        }
        let mut name = field.name.clone();
        let mut suffix = 2;
        while merged.extra_fields.iter().any(|f| f.name == name) {
            name = format!("{} ({suffix})", field.name);
            suffix += 1;
        }
        merged.extra_fields.push(ItemExtraField {
            name,
            content: field.content,
        });
    }

    Ok(MergePlan {
        primary_id: primary.item_id.clone(),
        secondary_id: secondary.item_id.clone(),
        actions,
        merged_item: merged,
    })
}

/// Plans merging a group of items: `primary` is the base, `secondaries` are folded in, in the
/// given (visual) order. Returns the pairwise plans plus the final merged state, so the whole
/// group can be executed as one update of the primary followed by trashing the secondaries.
pub fn plan_group_merge(primary: &ItemForMerge, secondaries: &[ItemForMerge]) -> Result<GroupMergePlan, MergeError> {
    // Rejecting duplicates up front keeps the documented execution model (update the primary,
    // then trash the secondaries) safe: merging an item with itself is a field-wise no-op, so a
    // caller passing the primary's own id (or the same item twice) would otherwise silently trash
    // an item it just merged.
    let mut seen_ids = vec![primary.item_id.as_str()];
    for secondary in secondaries {
        if seen_ids.contains(&secondary.item_id.as_str()) {
            return Err(MergeError::DuplicateItem(format!(
                "Item {} appears more than once in the merge group.",
                secondary.item_id
            )));
        }
        seen_ids.push(secondary.item_id.as_str());
    }

    let mut current = primary.clone();
    let mut secondary_plans = Vec::with_capacity(secondaries.len());

    for secondary in secondaries {
        let plan = plan_item_merge(&current, secondary)?;
        current.item = plan.merged_item.clone();
        secondary_plans.push(plan);
    }

    Ok(GroupMergePlan {
        primary_id: primary.item_id.clone(),
        secondary_plans,
        merged_item: current.item,
    })
}

#[cfg(test)]
mod test {
    use proton_pass_types::{
        AutofillUrl, AutofillUrlMode, ItemData, ItemExtraField, ItemExtraFieldContent, LoginItem, NoteItem, Passkey,
    };

    use super::*;
    use crate::merge::MergeFieldAction;

    fn item_for_merge(item_id: &str, item: ItemData) -> ItemForMerge {
        ItemForMerge {
            item_id: item_id.to_string(),
            share_id: "share".to_string(),
            item,
        }
    }

    fn login_item(title: &str, login: LoginItem) -> ItemData {
        ItemData::new(
            title.to_string(),
            String::new(),
            "uuid".to_string(),
            ItemContent::Login(login),
            vec![],
        )
        .unwrap()
    }

    fn login(
        title: &str,
        username: &str,
        password: &str,
        totp_uri: &str,
        urls: &[&str],
        autofill_urls: &[(&str, AutofillUrlMode)],
        passkeys: &[Passkey],
    ) -> ItemForMerge {
        item_for_merge(
            title,
            login_item(
                title,
                LoginItem {
                    email: String::new(),
                    username: username.to_string(),
                    password: password.to_string(),
                    urls: urls.iter().map(|u| u.to_string()).collect(),
                    totp_uri: totp_uri.to_string(),
                    passkeys: passkeys.to_vec(),
                    autofill_urls: autofill_urls
                        .iter()
                        .map(|(url, mode)| AutofillUrl {
                            url: url.to_string(),
                            mode: *mode,
                        })
                        .collect(),
                },
            ),
        )
    }

    fn passkey(key_id: &str) -> Passkey {
        Passkey {
            key_id: key_id.to_string(),
            content: vec![],
            domain: "example.com".to_string(),
            rp_id: "example.com".to_string(),
            rp_name: String::new(),
            user_name: String::new(),
            user_display_name: String::new(),
            user_id: vec![],
            create_time: 0,
            note: String::new(),
            credential_id: vec![],
            user_handle: vec![],
            creation_data: None,
        }
    }

    fn note_item(title: &str, note: &str, extra_fields: Vec<ItemExtraField>) -> ItemForMerge {
        item_for_merge(
            "note",
            ItemData::new(
                title.to_string(),
                note.to_string(),
                "uuid".to_string(),
                ItemContent::Note(NoteItem),
                extra_fields,
            )
            .unwrap(),
        )
    }

    fn extra_field(name: &str, content: ItemExtraFieldContent) -> ItemExtraField {
        ItemExtraField {
            name: name.to_string(),
            content,
        }
    }

    fn merged_login(plan: &MergePlan) -> &LoginItem {
        match &plan.merged_item.content {
            ItemContent::Login(login) => login,
            _ => panic!("expected a login item"),
        }
    }

    fn find_action(plan: &MergePlan, field: MergeFieldKind) -> &MergeFieldAction {
        plan.actions
            .iter()
            .find(|a| a.field == field)
            .expect("action should exist")
    }

    #[test]
    fn titles_differ_keeps_primary_title() {
        let primary = login("Amazon", "bob", "pw", "", &[], &[], &[]);
        let secondary = login("Amazon (old)", "bob", "pw", "", &[], &[], &[]);

        let plan = plan_item_merge(&primary, &secondary).unwrap();

        assert_eq!(plan.merged_item.title, "Amazon");
        assert_eq!(
            find_action(&plan, MergeFieldKind::Title).kind,
            MergeActionKind::KeepPrimary
        );
    }

    #[test]
    fn different_totp_secret_is_preserved_as_totp_custom_field() {
        let primary = login("Amazon", "bob", "pw", "otpauth://totp/primary", &[], &[], &[]);
        let secondary = login("Amazon", "bob", "pw", "otpauth://totp/secondary", &[], &[], &[]);

        let plan = plan_item_merge(&primary, &secondary).unwrap();

        assert_eq!(merged_login(&plan).totp_uri, "otpauth://totp/primary");
        assert_eq!(
            plan.merged_item.extra_fields,
            vec![extra_field(
                "Amazon - TOTP",
                ItemExtraFieldContent::Totp("otpauth://totp/secondary".to_string())
            )]
        );
        assert_eq!(
            find_action(&plan, MergeFieldKind::Totp).kind,
            MergeActionKind::ConflictToCustomField
        );
    }

    #[test]
    fn different_item_types_are_rejected() {
        let primary = login("Amazon", "bob", "pw", "", &[], &[], &[]);
        let secondary = note_item("Amazon", "note", vec![]);

        let err = plan_item_merge(&primary, &secondary).unwrap_err();

        assert_eq!(
            err,
            MergeError::IncompatibleItemTypes("Cannot merge a Note item into a Login item.".to_string())
        );
    }

    #[test]
    fn identical_items_produce_an_unchanged_merge() {
        let primary = login(
            "Amazon",
            "bob",
            "pw",
            "otpauth://totp/x",
            &["https://amazon.com"],
            &[],
            &[passkey("k1")],
        );
        let secondary = login(
            "Amazon",
            "bob",
            "pw",
            "otpauth://totp/x",
            &["https://amazon.com"],
            &[],
            &[passkey("k1")],
        );

        let plan = plan_item_merge(&primary, &secondary).unwrap();

        let expected_urls = vec![AutofillUrl {
            url: "https://amazon.com".to_string(),
            mode: AutofillUrlMode::Default,
        }];
        assert_eq!(merged_login(&plan).urls, vec!["https://amazon.com".to_string()]);
        assert_eq!(merged_login(&plan).autofill_urls, expected_urls);
        assert!(plan.merged_item.extra_fields.is_empty());
        assert!(plan.actions.iter().all(|a| a.kind == MergeActionKind::Identical));
    }

    #[test]
    fn primary_ids_and_uuid_are_preserved_through_the_merge() {
        let mut primary = login("Amazon", "bob", "pw", "", &[], &[], &[]);
        primary.item.item_uuid = "primary-uuid".to_string();
        let mut secondary = login("Amazon", "bob", "pw", "", &[], &[], &[]);
        secondary.item.item_uuid = "secondary-uuid".to_string();

        let plan = plan_item_merge(&primary, &secondary).unwrap();

        assert_eq!(plan.primary_id, primary.item_id);
        assert_eq!(plan.secondary_id, secondary.item_id);
        assert_eq!(plan.merged_item.item_uuid, "primary-uuid");
    }

    #[test]
    fn three_item_group_folds_in_visual_order() {
        let primary = login(
            "Amazon",
            "bob",
            "pw",
            "otpauth://totp/primary",
            &["https://amazon.com"],
            &[],
            &[],
        );
        let secondary_1 = login(
            "Amazon 2",
            "bobby",
            "pw2",
            "otpauth://totp/secondary-1",
            &["https://smile.amazon.com"],
            &[],
            &[],
        );
        let secondary_2 = login(
            "Amazon 3",
            "bobbie",
            "pw3",
            "otpauth://totp/secondary-2",
            &["https://shop.com"],
            &[],
            &[],
        );

        let group = plan_group_merge(&primary, &[secondary_1, secondary_2]).unwrap();

        assert_eq!(group.secondary_plans.len(), 2);
        // Step 2 merges against step 1's result, not against the original primary.
        assert_eq!(group.secondary_plans[1].merged_item.note, "");
        let login = match &group.merged_item.content {
            ItemContent::Login(login) => login,
            _ => panic!("expected a login item"),
        };
        // Urls from both secondaries, primary's first, in order, mirrored into autofill_urls.
        assert_eq!(
            login.urls,
            vec!["https://amazon.com", "https://smile.amazon.com", "https://shop.com"]
        );
        assert_eq!(
            login.autofill_urls.iter().map(|u| u.url.as_str()).collect::<Vec<_>>(),
            vec!["https://amazon.com", "https://smile.amazon.com", "https://shop.com"]
        );
        // Both secondaries' conflicting values survive, each named after its source.
        assert_eq!(
            group.merged_item.extra_fields,
            vec![
                extra_field("Amazon 2 - Username", ItemExtraFieldContent::Text("bobby".into())),
                extra_field("Amazon 2 - Password", ItemExtraFieldContent::Hidden("pw2".into())),
                extra_field(
                    "Amazon 2 - TOTP",
                    ItemExtraFieldContent::Totp("otpauth://totp/secondary-1".into())
                ),
                extra_field("Amazon 3 - Username", ItemExtraFieldContent::Text("bobbie".into())),
                extra_field("Amazon 3 - Password", ItemExtraFieldContent::Hidden("pw3".into())),
                extra_field(
                    "Amazon 3 - TOTP",
                    ItemExtraFieldContent::Totp("otpauth://totp/secondary-2".into())
                ),
            ]
        );
        assert_eq!(login.totp_uri, "otpauth://totp/primary");
    }

    #[test]
    fn group_with_no_secondaries_returns_primary_unchanged() {
        let primary = login("Amazon", "bob", "pw", "", &[], &[], &[]);

        let group = plan_group_merge(&primary, &[]).unwrap();

        assert!(group.secondary_plans.is_empty());
        assert_eq!(group.merged_item, primary.item);
    }

    #[test]
    fn group_fails_when_any_secondary_has_a_different_type() {
        let primary = login("Amazon", "bob", "pw", "", &[], &[], &[]);
        let secondary_1 = login("Amazon 2", "bob", "pw", "", &[], &[], &[]);
        let secondary_2 = note_item("Amazon 3", "note", vec![]);

        let err = plan_group_merge(&primary, &[secondary_1, secondary_2]).unwrap_err();

        assert!(matches!(err, MergeError::IncompatibleItemTypes(_)));
    }

    #[test]
    fn group_rejects_secondary_that_is_the_primary_itself() {
        let primary = login("Amazon", "bob", "pw", "", &[], &[], &[]);
        let secondary = login("Amazon (old)", "bob", "pw", "", &[], &[], &[]);
        let secondary_with_primary_id = ItemForMerge {
            item_id: primary.item_id.clone(),
            ..secondary.clone()
        };

        let err = plan_group_merge(&primary, &[secondary, secondary_with_primary_id]).unwrap_err();

        assert!(matches!(err, MergeError::DuplicateItem(_)));
    }

    #[test]
    fn group_rejects_duplicated_secondaries() {
        let primary = login("Amazon", "bob", "pw", "", &[], &[], &[]);
        let secondary = login("Amazon (old)", "bob", "pw", "", &[], &[], &[]);

        let err = plan_group_merge(&primary, &[secondary.clone(), secondary]).unwrap_err();

        assert!(matches!(err, MergeError::DuplicateItem(_)));
    }

    #[test]
    fn urls_and_autofill_urls_are_merged_into_autofill_urls() {
        let primary = login(
            "Amazon",
            "bob",
            "pw",
            "otpauth://totp/x",
            &["https://amazon.com"],
            &[("https://autofill.com", AutofillUrlMode::Default)],
            &[],
        );
        let secondary = login(
            "Amazon",
            "bob",
            "pw",
            "otpauth://totp/x",
            &["https://amazon.com"],
            &[("https://new.com", AutofillUrlMode::Exact)],
            &[],
        );

        let plan = plan_item_merge(&primary, &secondary).unwrap();

        assert_eq!(
            plan.actions
                .iter()
                .find(|a| a.field == MergeFieldKind::AutofillUrls)
                .unwrap()
                .kind,
            MergeActionKind::Union
        );
        assert!(plan.actions.iter().all(|a| a.field != MergeFieldKind::Urls));
        let login = merged_login(&plan);
        assert_eq!(
            login.urls,
            vec!["https://autofill.com", "https://amazon.com", "https://new.com"]
        );
        assert_eq!(
            login
                .autofill_urls
                .iter()
                .map(|u| (u.url.as_str(), u.mode))
                .collect::<Vec<_>>(),
            vec![
                ("https://autofill.com", AutofillUrlMode::Default),
                ("https://amazon.com", AutofillUrlMode::Default),
                ("https://new.com", AutofillUrlMode::Exact),
            ]
        );
    }
}
