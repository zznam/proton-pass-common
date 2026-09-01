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

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};

use proton_pass_types::{ItemContent, ItemData, LoginItem};

use crate::domain::get_root_domain;

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemForDuplicateDetection {
    pub item_id: String,
    pub share_id: String,
    pub item: ItemData,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateItemIdentifier {
    pub item_id: String,
    pub share_id: String,
}

#[proton_pass_derive::ffi_type]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateItemGroup {
    pub items: Vec<DuplicateItemIdentifier>,
}

// Groups items into duplicate clusters. Each item starts in its own group. Every `union` call
// merges two groups, so items don't need to be directly compared to end up in the same group:
// if A matches B and B matches C, A and C are grouped even though they were never compared.
struct UnionFind {
    // `parent[i]` points to another item in the same group. Following `parent` links repeatedly
    // reaches the group's root: an item whose `parent` points to itself.
    parent: Vec<usize>,
    // Size of the tree rooted at `i`, only meaningful when `i` is a root. Used by `union` to
    // keep trees shallow.
    size: Vec<usize>,
}

impl UnionFind {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
            size: vec![1; size],
        }
    }

    // Returns the root of the group `x` belongs to.
    fn find(&mut self, mut x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        // Iterative two-pass path compression: walk to the root first, then point everything
        // along the way directly at it. Recursing here instead could blow the stack on a long
        // chain (thousands of items that only match their neighbor).
        while self.parent[x] != root {
            let next = self.parent[x];
            self.parent[x] = root;
            x = next;
        }
        root
    }

    /// Merges the groups that `a` and `b` belong to into a single group.
    fn union(&mut self, a: usize, b: usize) {
        let (mut root_a, mut root_b) = (self.find(a), self.find(b));
        if root_a == root_b {
            return;
        }
        // Union by size: attach the smaller tree under the bigger one, so trees stay shallow and
        // `find` stays cheap even without relying on path compression alone.
        if self.size[root_a] < self.size[root_b] {
            std::mem::swap(&mut root_a, &mut root_b);
        }
        self.parent[root_b] = root_a;
        self.size[root_a] += self.size[root_b];
    }
}

// Login urls used to be a plain string list; `autofill_urls` is the field going forward, so it
// takes precedence whenever it is populated.
fn login_urls(login: &LoginItem) -> Vec<&str> {
    if !login.autofill_urls.is_empty() {
        login.autofill_urls.iter().map(|u| u.url.as_str()).collect()
    } else {
        login.urls.iter().map(String::as_str).collect()
    }
}

// Whether a login imposes a url constraint at all, computed once per item so the comparison loop
// only does cheap set intersections instead of re-parsing urls for every pair.
enum LoginUrlConstraint {
    // The login has no urls, so it never rules out a match on its own.
    NoUrls,
    // The login has urls, but none of them parsed into a domain: unlike `NoUrls`, this must never
    // be treated as "no constraint", or a login with junk urls would match anything that shares
    // its identity and password.
    UnparseableUrls,
    Domains(HashSet<String>),
}

fn login_url_constraint(login: &LoginItem) -> LoginUrlConstraint {
    let urls = login_urls(login);
    if urls.is_empty() {
        return LoginUrlConstraint::NoUrls;
    }

    let domains: HashSet<String> = urls.iter().filter_map(|url| get_root_domain(url).ok()).collect();
    if domains.is_empty() {
        LoginUrlConstraint::UnparseableUrls
    } else {
        LoginUrlConstraint::Domains(domains)
    }
}

// Android apps allowed to autofill this item, if any. Package names are the Android analog of a
// root domain, so they're used the same way: as an alternative way to confirm two logins are for
// the same service.
fn android_packages(item: &ItemData) -> HashSet<String> {
    item.platform_specific
        .as_ref()
        .and_then(|platform| platform.android.as_ref())
        .map(|android| {
            android
                .allowed_apps
                .iter()
                .map(|app| app.package_name.clone())
                .collect()
        })
        .unwrap_or_default()
}

// Urls that failed to parse never count as related to anything, on either side, regardless of
// Android data: unlike a genuinely empty url, this is data the user entered that we couldn't
// make sense of, so it's treated as a hard veto rather than something Android can rescue.
//
// When both sides have urls that parsed, only those domains decide the outcome; Android is never
// consulted, so a clear cross-site url mismatch (e.g. amazon.com vs uber.com) can't be overridden
// by a coincidentally matching package name.
//
// Otherwise (at least one side has no url at all), Android package overlap decides it: with no
// Android data on either side either, there's nothing to disagree on, so identity + password
// alone are enough; otherwise the packages must actually overlap.
fn login_urls_related(
    a_urls: &LoginUrlConstraint,
    b_urls: &LoginUrlConstraint,
    a_packages: &HashSet<String>,
    b_packages: &HashSet<String>,
) -> bool {
    match (a_urls, b_urls) {
        (LoginUrlConstraint::UnparseableUrls, _) | (_, LoginUrlConstraint::UnparseableUrls) => false,
        (LoginUrlConstraint::Domains(a_domains), LoginUrlConstraint::Domains(b_domains)) => {
            a_domains.intersection(b_domains).next().is_some()
        }
        (LoginUrlConstraint::NoUrls, LoginUrlConstraint::NoUrls) if a_packages.is_empty() && b_packages.is_empty() => {
            true
        }
        _ => a_packages.intersection(b_packages).next().is_some(),
    }
}

fn same_identity_and_password(a: &LoginItem, b: &LoginItem) -> bool {
    let same_identity =
        (!a.username.is_empty() && a.username == b.username) || (!a.email.is_empty() && a.email == b.email);

    same_identity && !a.password.is_empty() && a.password == b.password
}

// A blank item (no note, no custom fields, no type-specific content) is never treated as a
// duplicate of another blank item: e.g. two empty notes titled "Wifi codes" and "Recovery"
// aren't meaningfully the same item.
fn is_empty_item(item: &ItemData) -> bool {
    item.note.is_empty() && item.extra_fields.is_empty() && item.content.pretty_print().is_empty()
}

// Caches each login's url constraint on first use instead of computing it upfront for every
// item, since most items in a comparison loop never reach the url check (e.g. their identity or
// password already differs), and computing eagerly would waste that parsing work.
struct DedupContext<'a> {
    items: &'a [ItemForDuplicateDetection],
    login_url_constraints: Vec<OnceCell<LoginUrlConstraint>>,
    android_packages: Vec<OnceCell<HashSet<String>>>,
}

impl<'a> DedupContext<'a> {
    fn new(items: &'a [ItemForDuplicateDetection]) -> Self {
        Self {
            items,
            login_url_constraints: items.iter().map(|_| OnceCell::new()).collect(),
            android_packages: items.iter().map(|_| OnceCell::new()).collect(),
        }
    }

    fn login_url_constraint(&self, index: usize) -> &LoginUrlConstraint {
        self.login_url_constraints[index].get_or_init(|| match &self.items[index].item.content {
            ItemContent::Login(login) => login_url_constraint(login),
            _ => LoginUrlConstraint::NoUrls,
        })
    }

    fn android_packages(&self, index: usize) -> &HashSet<String> {
        self.android_packages[index].get_or_init(|| android_packages(&self.items[index].item))
    }

    fn is_duplicate(&self, i: usize, j: usize) -> bool {
        let a = &self.items[i].item;
        let b = &self.items[j].item;

        match (&a.content, &b.content) {
            (ItemContent::Login(login_a), ItemContent::Login(login_b)) => {
                same_identity_and_password(login_a, login_b)
                    && login_urls_related(
                        self.login_url_constraint(i),
                        self.login_url_constraint(j),
                        self.android_packages(i),
                        self.android_packages(j),
                    )
            }
            _ => a.content == b.content && a.note == b.note && a.extra_fields == b.extra_fields && !is_empty_item(a),
        }
    }
}

// Coarse keys an item could be a duplicate under. Two items can only be duplicates if they share
// at least one key, so bucketing candidates by key turns the full O(n^2) comparison into one pass
// to build the buckets plus pairwise checks only within each bucket, which is far cheaper than
// n^2 whenever a vault isn't dominated by one giant bucket of near-identical items.
//
// A login contributes up to two keys (one for username, one for email) since either can establish
// a duplicate independently of the other. Debug output is used as the key for non-login items
// instead of a hand-rolled hash because `content`/`extra_fields` don't implement `Hash`, and
// derived `Debug` is guaranteed to match derived `PartialEq` field-for-field.
fn bucket_keys(item: &ItemData) -> Vec<String> {
    match &item.content {
        ItemContent::Alias(_) => vec![],
        ItemContent::Login(login) => {
            let mut keys = Vec::with_capacity(2);
            if !login.username.is_empty() && !login.password.is_empty() {
                keys.push(format!("login|username|{}|{}", login.username, login.password));
            }
            if !login.email.is_empty() && !login.password.is_empty() {
                keys.push(format!("login|email|{}|{}", login.email, login.password));
            }
            keys
        }
        _ if is_empty_item(item) => vec![],
        _ => vec![format!("{:?}|{:?}|{:?}", item.content, item.note, item.extra_fields)],
    }
}

pub fn find_duplicate_items(items: Vec<ItemForDuplicateDetection>) -> Vec<DuplicateItemGroup> {
    let context = DedupContext::new(&items);
    let mut union_find = UnionFind::new(items.len());

    let mut buckets: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, entry) in items.iter().enumerate() {
        for key in bucket_keys(&entry.item) {
            buckets.entry(key).or_default().push(i);
        }
    }

    for bucket in buckets.values() {
        for (a, &i) in bucket.iter().enumerate() {
            for &j in &bucket[a + 1..] {
                if context.is_duplicate(i, j) {
                    union_find.union(i, j);
                }
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..items.len() {
        let root = union_find.find(i);
        groups.entry(root).or_default().push(i);
    }

    groups
        .into_values()
        .filter(|indices| indices.len() > 1)
        .map(|indices| DuplicateItemGroup {
            items: indices
                .into_iter()
                .map(|i| DuplicateItemIdentifier {
                    item_id: items[i].item_id.clone(),
                    share_id: items[i].share_id.clone(),
                })
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod test {
    use proton_pass_types::{
        AliasItem, AllowedAndroidApp, AndroidSpecific, CustomItem, CustomSection, NoteItem, PlatformSpecific,
        SshKeyItem, WifiItem, WifiSecurity,
    };

    use super::*;

    fn item(item_id: &str, content: ItemContent) -> ItemForDuplicateDetection {
        item_with_note(item_id, content, "")
    }

    fn with_android_apps(mut entry: ItemForDuplicateDetection, packages: &[&str]) -> ItemForDuplicateDetection {
        entry.item.platform_specific = Some(PlatformSpecific {
            android: Some(AndroidSpecific {
                allowed_apps: packages
                    .iter()
                    .map(|package_name| AllowedAndroidApp {
                        package_name: package_name.to_string(),
                        hashes: vec![],
                        app_name: String::new(),
                    })
                    .collect(),
            }),
        });
        entry
    }

    fn item_with_note(item_id: &str, content: ItemContent, note: &str) -> ItemForDuplicateDetection {
        ItemForDuplicateDetection {
            item_id: item_id.to_string(),
            share_id: "share".to_string(),
            item: ItemData::new(
                "title".to_string(),
                note.to_string(),
                "uuid".to_string(),
                content,
                vec![],
            )
            .unwrap(),
        }
    }

    fn login(username: &str, email: &str, password: &str, urls: &[&str]) -> ItemContent {
        ItemContent::Login(LoginItem {
            email: email.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            totp_uri: String::new(),
            passkeys: vec![],
            autofill_urls: vec![],
        })
    }

    fn group_ids(groups: &[DuplicateItemGroup]) -> Vec<Vec<String>> {
        let mut result: Vec<Vec<String>> = groups
            .iter()
            .map(|g| {
                let mut ids: Vec<String> = g.items.iter().map(|i| i.item_id.clone()).collect();
                ids.sort();
                ids
            })
            .collect();
        result.sort();
        result
    }

    #[test]
    fn logins_with_same_username_password_and_related_urls_are_duplicates() {
        let items = vec![
            item("1", login("bob", "", "pw", &["https://amazon.com/login"])),
            item("2", login("bob", "", "pw", &["https://www.amazon.com/account"])),
        ];

        let groups = find_duplicate_items(items);
        assert_eq!(group_ids(&groups), vec![vec!["1".to_string(), "2".to_string()]]);
    }

    #[test]
    fn logins_with_same_identity_and_password_but_unrelated_urls_are_not_duplicates() {
        let items = vec![
            item("1", login("bob", "", "pw", &["https://amazon.com/login"])),
            item("2", login("bob", "", "pw", &["https://uber.com/login"])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_matching_by_email_instead_of_username_are_duplicates() {
        let items = vec![
            item("1", login("", "bob@proton.me", "pw", &[])),
            item("2", login("", "bob@proton.me", "pw", &[])),
        ];

        let groups = find_duplicate_items(items);
        assert_eq!(group_ids(&groups), vec![vec!["1".to_string(), "2".to_string()]]);
    }

    #[test]
    fn logins_with_different_identity_are_not_duplicates() {
        let items = vec![
            item("1", login("bob", "", "pw", &[])),
            item("2", login("alice", "", "pw", &[])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_different_password_are_not_duplicates() {
        let items = vec![
            item("1", login("bob", "", "pw1", &[])),
            item("2", login("bob", "", "pw2", &[])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_same_identity_but_empty_password_are_not_duplicates() {
        let items = vec![
            item("1", login("bob", "", "", &[])),
            item("2", login("bob", "", "", &[])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_unparseable_urls_are_not_duplicates_even_with_matching_identity() {
        let items = vec![
            item("1", login("bob", "", "pw", &["not a url"])),
            item("2", login("bob", "", "pw", &["also not a url"])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_unparseable_urls_are_not_duplicates_of_logins_with_no_urls() {
        let items = vec![
            item("1", login("bob", "", "pw", &["not a url"])),
            item("2", login("bob", "", "pw", &[])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_unparseable_urls_are_not_duplicates_even_with_matching_android_package() {
        let items = vec![
            with_android_apps(item("1", login("bob", "", "pw", &["not a url"])), &["com.example.app"]),
            with_android_apps(
                item("2", login("bob", "", "pw", &["also not a url"])),
                &["com.example.app"],
            ),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_unparseable_urls_and_different_android_packages_are_not_duplicates() {
        let items = vec![
            with_android_apps(
                item("1", login("bob", "", "pw", &["not a url"])),
                &["com.example.amazon"],
            ),
            with_android_apps(
                item("2", login("bob", "", "pw", &["also not a url"])),
                &["com.example.uber"],
            ),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_unparseable_urls_and_android_package_on_only_one_side_are_not_duplicates() {
        let items = vec![
            with_android_apps(item("1", login("bob", "", "pw", &["not a url"])), &["com.example.app"]),
            item("2", login("bob", "", "pw", &["also not a url"])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_unrelated_url_domains_are_not_duplicates_even_with_matching_android_package() {
        let items = vec![
            with_android_apps(
                item("1", login("bob", "", "pw", &["https://amazon.com"])),
                &["com.example.app"],
            ),
            with_android_apps(
                item("2", login("bob", "", "pw", &["https://uber.com"])),
                &["com.example.app"],
            ),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn logins_with_no_urls_on_both_sides_and_no_android_data_are_duplicates() {
        let items = vec![
            item("1", login("bob", "", "pw", &[])),
            item("2", login("bob", "", "pw", &[])),
        ];

        let groups = find_duplicate_items(items);
        assert_eq!(group_ids(&groups), vec![vec!["1".to_string(), "2".to_string()]]);
    }

    #[test]
    fn logins_with_no_urls_on_both_sides_but_mismatched_android_packages_are_not_duplicates() {
        let items = vec![
            with_android_apps(item("1", login("bob", "", "pw", &[])), &["com.example.amazon"]),
            with_android_apps(item("2", login("bob", "", "pw", &[])), &["com.example.uber"]),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn login_with_no_url_and_login_with_url_are_not_duplicates_without_a_matching_android_package() {
        let items = vec![
            item("1", login("bob", "", "pw", &[])),
            item("2", login("bob", "", "pw", &["https://amazon.com"])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn login_with_no_url_and_login_with_url_are_duplicates_with_a_matching_android_package() {
        let items = vec![
            with_android_apps(item("1", login("bob", "", "pw", &[])), &["com.example.app"]),
            with_android_apps(
                item("2", login("bob", "", "pw", &["https://amazon.com"])),
                &["com.example.app"],
            ),
        ];

        let groups = find_duplicate_items(items);
        assert_eq!(group_ids(&groups), vec![vec!["1".to_string(), "2".to_string()]]);
    }

    #[test]
    fn logins_are_transitively_grouped() {
        let items = vec![
            item("1", login("bob", "", "pw", &["https://amazon.com"])),
            item("2", login("bob", "", "pw", &["https://amazon.com", "https://uber.com"])),
            item("3", login("bob", "", "pw", &["https://uber.com"])),
        ];

        let groups = find_duplicate_items(items);
        assert_eq!(
            group_ids(&groups),
            vec![vec!["1".to_string(), "2".to_string(), "3".to_string()]]
        );
    }

    #[test]
    fn union_find_handles_long_chains_without_stack_overflow() {
        let count = 1_000_000;
        let mut union_find = UnionFind::new(count);
        for i in 0..count - 1 {
            union_find.union(i, i + 1);
        }

        let root = union_find.find(0);
        for i in 1..count {
            assert_eq!(union_find.find(i), root);
        }
    }

    #[test]
    fn notes_with_same_note_and_extra_fields_are_duplicates() {
        let items = vec![
            item_with_note("1", ItemContent::Note(NoteItem), "same note"),
            item_with_note("2", ItemContent::Note(NoteItem), "same note"),
        ];

        let groups = find_duplicate_items(items);
        assert_eq!(group_ids(&groups), vec![vec!["1".to_string(), "2".to_string()]]);
    }

    #[test]
    fn notes_with_different_note_are_not_duplicates() {
        let items = vec![
            item_with_note("1", ItemContent::Note(NoteItem), "note a"),
            item_with_note("2", ItemContent::Note(NoteItem), "note b"),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn empty_generic_items_are_never_duplicates() {
        let items = vec![
            item_with_note("1", ItemContent::Note(NoteItem), ""),
            item_with_note("2", ItemContent::Note(NoteItem), ""),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn aliases_are_never_duplicates() {
        let items = vec![
            item("1", ItemContent::Alias(AliasItem)),
            item("2", ItemContent::Alias(AliasItem)),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn different_item_types_are_never_duplicates() {
        let items = vec![
            item("1", login("bob", "bob@proton.me", "pw", &[])),
            item_with_note("2", ItemContent::Note(NoteItem), ""),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn wifi_and_ssh_are_dedicated_types_and_never_match_each_other() {
        let items = vec![
            item(
                "1",
                ItemContent::Wifi(WifiItem {
                    ssid: "network".to_string(),
                    password: "pw".to_string(),
                    security: WifiSecurity::WPA2,
                    sections: vec![],
                }),
            ),
            item(
                "2",
                ItemContent::SshKey(SshKeyItem {
                    private_key: "priv".to_string(),
                    public_key: "pub".to_string(),
                    sections: vec![],
                }),
            ),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }

    #[test]
    fn custom_items_with_same_sections_are_duplicates() {
        let sections = vec![CustomSection {
            section_name: "section".to_string(),
            section_fields: vec![],
        }];
        let items = vec![
            item(
                "1",
                ItemContent::Custom(CustomItem {
                    sections: sections.clone(),
                }),
            ),
            item("2", ItemContent::Custom(CustomItem { sections })),
        ];

        let groups = find_duplicate_items(items);
        assert_eq!(group_ids(&groups), vec![vec!["1".to_string(), "2".to_string()]]);
    }

    #[test]
    fn items_with_no_duplicates_are_excluded_from_results() {
        let items = vec![
            item("1", login("bob", "", "pw", &[])),
            item("2", login("alice", "", "pw2", &[])),
        ];

        assert!(find_duplicate_items(items).is_empty());
    }
}
