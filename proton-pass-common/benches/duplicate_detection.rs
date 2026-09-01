use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use proton_pass_common::duplicate::{ItemForDuplicateDetection, find_duplicate_items};
use proton_pass_types::{
    CreditCardItem, CustomItem, CustomSection, IdentityItem, ItemContent, ItemData, ItemExtraField, LoginItem, NoteItem,
};
use std::hint::black_box;

fn login_item(id: usize, username: String, password: String, urls: Vec<String>) -> ItemForDuplicateDetection {
    let content = ItemContent::Login(LoginItem {
        email: String::new(),
        username,
        password,
        urls,
        totp_uri: String::new(),
        passkeys: vec![],
        autofill_urls: vec![],
    });
    ItemForDuplicateDetection {
        item_id: format!("item-{id}"),
        share_id: "share".to_string(),
        item: ItemData::new(
            format!("Login {id}"),
            String::new(),
            format!("uuid-{id}"),
            content,
            vec![],
        )
        .unwrap(),
    }
}

fn note_item(id: usize, note: &str) -> ItemForDuplicateDetection {
    ItemForDuplicateDetection {
        item_id: format!("item-{id}"),
        share_id: "share".to_string(),
        item: ItemData::new(
            format!("Note {id}"),
            note.to_string(),
            format!("uuid-{id}"),
            ItemContent::Note(NoteItem),
            vec![],
        )
        .unwrap(),
    }
}

fn credit_card_item(id: usize, number: &str) -> ItemForDuplicateDetection {
    let content = ItemContent::CreditCard(CreditCardItem {
        cardholder_name: "Jane Doe".to_string(),
        card_type: Default::default(),
        number: number.to_string(),
        verification_number: "123".to_string(),
        expiration_date: "12/30".to_string(),
        pin: String::new(),
    });
    ItemForDuplicateDetection {
        item_id: format!("item-{id}"),
        share_id: "share".to_string(),
        item: ItemData::new(
            format!("Card {id}"),
            String::new(),
            format!("uuid-{id}"),
            content,
            vec![],
        )
        .unwrap(),
    }
}

fn identity_item(id: usize, full_name: &str) -> ItemForDuplicateDetection {
    let content = ItemContent::Identity(Box::new(IdentityItem {
        full_name: full_name.to_string(),
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
    }));
    ItemForDuplicateDetection {
        item_id: format!("item-{id}"),
        share_id: "share".to_string(),
        item: ItemData::new(
            format!("Identity {id}"),
            String::new(),
            format!("uuid-{id}"),
            content,
            vec![],
        )
        .unwrap(),
    }
}

fn custom_item(id: usize, section_name: &str) -> ItemForDuplicateDetection {
    let content = ItemContent::Custom(CustomItem {
        sections: vec![CustomSection {
            section_name: section_name.to_string(),
            section_fields: vec![ItemExtraField {
                name: "field".to_string(),
                content: proton_pass_types::ItemExtraFieldContent::Text("value".to_string()),
            }],
        }],
    });
    ItemForDuplicateDetection {
        item_id: format!("item-{id}"),
        share_id: "share".to_string(),
        item: ItemData::new(
            format!("Custom {id}"),
            String::new(),
            format!("uuid-{id}"),
            content,
            vec![],
        )
        .unwrap(),
    }
}

/// No two items match, so every pair must be compared without ever finding a duplicate: the
/// worst case for the pairwise union-find scan.
fn no_duplicates(n: usize) -> Vec<ItemForDuplicateDetection> {
    (0..n)
        .map(|i| {
            login_item(
                i,
                format!("user{i}"),
                format!("pw{i}"),
                vec![format!("https://site{i}.com")],
            )
        })
        .collect()
}

/// Every item has exactly one duplicate sharing its identity, password and root domain.
fn all_duplicate_pairs(n: usize) -> Vec<ItemForDuplicateDetection> {
    (0..n)
        .map(|i| {
            let pair = i / 2;
            login_item(
                i,
                format!("user{pair}"),
                format!("pw{pair}"),
                vec![format!("https://site{pair}.com/login")],
            )
        })
        .collect()
}

/// A vault-shaped mix of item types with duplicates scattered across a handful of them.
fn mixed_vault(n: usize) -> Vec<ItemForDuplicateDetection> {
    // `slot` (not `i`) drives each type's modulo grouping: since `i / 5` isn't correlated with
    // `i % 5`, each type gets an independent, evenly distributed set of duplicate clusters
    // instead of accidentally collapsing into a handful of huge ones (e.g. `i % 20` when `i % 5`
    // already picks the type would only ever hit 4 of the 20 residues).
    (0..n)
        .map(|i| {
            let slot = i / 5;
            match i % 5 {
                0 => login_item(
                    i,
                    format!("user{}", slot % 40),
                    format!("pw{}", slot % 40),
                    vec![format!("https://site{}.com", slot % 40)],
                ),
                1 => note_item(i, &format!("note body {}", slot % 30)),
                2 => credit_card_item(i, &format!("411111111111{:04}", slot % 25)),
                3 => identity_item(i, &format!("Person {}", slot % 20)),
                _ => custom_item(i, &format!("section {}", slot % 15)),
            }
        })
        .collect()
}

fn duplicate_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("duplicate_detection");

    for size in [200usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(size as u64));

        let unique = no_duplicates(size);
        group.bench_function(format!("no_duplicates_{size}"), |b| {
            b.iter_batched(
                || unique.clone(),
                |items| black_box(find_duplicate_items(items)),
                BatchSize::LargeInput,
            )
        });

        let pairs = all_duplicate_pairs(size);
        group.bench_function(format!("all_duplicate_pairs_{size}"), |b| {
            b.iter_batched(
                || pairs.clone(),
                |items| black_box(find_duplicate_items(items)),
                BatchSize::LargeInput,
            )
        });

        let mixed = mixed_vault(size);
        group.bench_function(format!("mixed_vault_{size}"), |b| {
            b.iter_batched(
                || mixed.clone(),
                |items| black_box(find_duplicate_items(items)),
                BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

criterion_group!(benches, duplicate_detection);
criterion_main!(benches);
