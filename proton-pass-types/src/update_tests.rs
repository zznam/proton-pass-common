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

//! Synthetic regression tests for the "update without losing unknown fields" technique used by the
//! `perform_update` functions.
//!
//! Real protos can't be used to exercise this without editing them, so two unrelated copies of a
//! synthetic schema are used instead:
//!  - `synthetic_known`: what an older build of the library knows about.
//!  - `synthetic_extended`: a newer schema with extra fields of every shape (scalar, optional,
//!    repeated, message, map, oneof variant, enum value, and fields nested inside known messages).
//!
//! Each test builds the data with the extended schema (as a newer client would have written it),
//! updates it through the known schema (as this library would), and parses the result with the
//! extended schema again to check what survived.
//!
//! The tests exercise [`update_preserving_unknown`], which every `perform_update` delegates to.
//! They also pin the protobuf reflection and unknown-field behaviour we rely on across upgrades.

use crate::protos::synthetic_extended::synthetic_extended_v1 as ext;
use crate::protos::synthetic_known::synthetic_known_v1 as known;
use crate::update::update_preserving_unknown;
use protobuf::{EnumOrUnknown, Message, MessageField};

fn perform_update(original: &[u8], new: &known::Record) -> Vec<u8> {
    update_preserving_unknown(original, new).unwrap()
}

fn inner(a: &str, b: &str) -> ext::Inner {
    ext::Inner {
        a: a.to_string(),
        b: b.to_string(),
        ..Default::default()
    }
}

/// A record as written by a newer client, with every unknown field populated.
fn extended_original() -> ext::Record {
    ext::Record {
        title: "old title".into(),
        note: Some("old note".into()),
        tags: vec!["t1".into(), "t2".into()],
        inner: MessageField::some(inner("old a", "inner b")),
        items: vec![inner("i1", "b1"), inner("i2", "b2")],
        count: 7,
        kind: EnumOrUnknown::new(ext::Kind::KIND_A),
        attrs: [("k".to_string(), "v".to_string())].into(),
        extra_scalar: "extra".into(),
        extra_optional: Some("extra opt".into()),
        extra_repeated: vec!["e1".into(), "e2".into()],
        extra_message: MessageField::some(ext::ExtraMessage {
            value: "extra msg".into(),
            ..Default::default()
        }),
        extra_map: [("ek".to_string(), "ev".to_string())].into(),
        extra_varint: 42,
        ..Default::default()
    }
}

/// The caller's view of the world after an edit: everything known gets sent, nothing unknown does.
fn known_update() -> known::Record {
    known::Record {
        title: "new title".into(),
        note: Some("new note".into()),
        tags: vec!["n1".into()],
        inner: MessageField::some(known::Inner {
            a: "new a".into(),
            ..Default::default()
        }),
        items: vec![known::Inner {
            a: "ni1".into(),
            ..Default::default()
        }],
        count: 9,
        kind: EnumOrUnknown::new(known::Kind::KIND_B),
        attrs: [("nk".to_string(), "nv".to_string())].into(),
        ..Default::default()
    }
}

fn update(original: &ext::Record, new: &known::Record) -> ext::Record {
    let updated = perform_update(&original.write_to_bytes().unwrap(), new);
    ext::Record::parse_from_bytes(&updated).unwrap()
}

fn assert_extras_untouched(result: &ext::Record) {
    let original = extended_original();
    assert_eq!(result.extra_scalar, original.extra_scalar);
    assert_eq!(result.extra_optional, original.extra_optional);
    assert_eq!(result.extra_repeated, original.extra_repeated);
    assert_eq!(result.extra_message, original.extra_message);
    assert_eq!(result.extra_map, original.extra_map);
    assert_eq!(result.extra_varint, original.extra_varint);
}

#[test]
fn schemas_are_wire_compatible() {
    // Sanity check on the fixtures: the known schema must see the extended one as unknown fields only
    let bytes = extended_original().write_to_bytes().unwrap();
    let as_known = known::Record::parse_from_bytes(&bytes).unwrap();
    assert_eq!(as_known.title, "old title");
    assert_eq!(as_known.note.as_deref(), Some("old note"));
    assert_eq!(as_known.tags, vec!["t1", "t2"]);
    assert_eq!(as_known.items.len(), 2);
    assert_eq!(as_known.attrs.get("k").map(String::as_str), Some("v"));
    for field in [100, 101, 102, 103, 104, 105] {
        assert!(
            as_known.special_fields.unknown_fields().get(field).is_some(),
            "field {field} should be unknown to the known schema"
        );
    }
}

#[test]
fn known_fields_are_updated_and_unknown_fields_preserved() {
    let result = update(&extended_original(), &known_update());

    assert_eq!(result.title, "new title");
    assert_eq!(result.note.as_deref(), Some("new note"));
    assert_eq!(result.count, 9);
    assert_eq!(result.kind.enum_value(), Ok(ext::Kind::KIND_B));
    assert_extras_untouched(&result);
}

#[test]
fn repeated_fields_are_replaced_not_appended() {
    let result = update(&extended_original(), &known_update());
    assert_eq!(result.tags, vec!["n1"]);
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].a, "ni1");
    // Unknown repeated fields live beside the known one and must not be touched either
    assert_eq!(result.extra_repeated, vec!["e1", "e2"]);
}

#[test]
fn repeated_field_can_be_emptied() {
    let mut new = known_update();
    new.tags.clear();
    new.items.clear();
    let result = update(&extended_original(), &new);
    assert!(result.tags.is_empty());
    assert!(result.items.is_empty());
    assert_eq!(result.extra_repeated, vec!["e1", "e2"]);
}

#[test]
fn map_fields_are_replaced_not_merged() {
    let result = update(&extended_original(), &known_update());
    assert_eq!(result.attrs.len(), 1);
    assert_eq!(result.attrs.get("nk").map(String::as_str), Some("nv"));
    assert_eq!(result.extra_map.get("ek").map(String::as_str), Some("ev"));
}

#[test]
fn optional_field_can_be_removed() {
    let mut new = known_update();
    new.note = None;
    let result = update(&extended_original(), &new);
    assert_eq!(result.note, None);
    assert_eq!(result.extra_optional.as_deref(), Some("extra opt"));
}

#[test]
fn optional_field_can_be_set_to_empty_string() {
    // `Some("")` is distinct from `None` for proto3 optional, and must survive
    let mut new = known_update();
    new.note = Some(String::new());
    let result = update(&extended_original(), &new);
    assert_eq!(result.note.as_deref(), Some(""));
}

#[test]
fn optional_field_can_be_added() {
    let mut original = extended_original();
    original.note = None;
    let result = update(&original, &known_update());
    assert_eq!(result.note.as_deref(), Some("new note"));
}

#[test]
fn scalars_can_be_reset_to_default() {
    let mut new = known_update();
    new.title.clear();
    new.count = 0;
    new.kind = EnumOrUnknown::default();
    let result = update(&extended_original(), &new);
    assert_eq!(result.title, "");
    assert_eq!(result.count, 0);
    assert_eq!(result.kind.enum_value(), Ok(ext::Kind::KIND_UNSPECIFIED));
    assert_extras_untouched(&result);
}

#[test]
fn nested_message_is_updated() {
    let result = update(&extended_original(), &known_update());
    assert_eq!(result.inner.a, "new a");
}

#[test]
fn nested_message_keeps_its_unknown_fields() {
    let result = update(&extended_original(), &known_update());
    assert_eq!(result.inner.a, "new a");
    assert_eq!(
        result.inner.b, "inner b",
        "unknown field nested in a known message was lost"
    );
}

#[test]
fn nested_message_scalar_can_be_reset_to_default() {
    let mut new = known_update();
    new.inner = MessageField::some(known::Inner::default());
    let result = update(&extended_original(), &new);
    assert_eq!(result.inner.a, "");
    assert_eq!(result.inner.b, "inner b");
}

#[test]
fn nested_message_can_be_removed() {
    let mut new = known_update();
    new.inner = MessageField::none();
    let result = update(&extended_original(), &new);
    assert!(result.inner.is_none());
}

#[test]
fn nested_message_can_be_added_when_originally_absent() {
    let mut original = extended_original();
    original.inner = MessageField::none();
    let result = update(&original, &known_update());
    assert_eq!(result.inner.a, "new a");
}

#[test]
fn message_inside_repeated_field_loses_its_nested_unknown_fields() {
    // Known limitation, pinned so it doesn't change unnoticed: repeated fields are replaced
    // wholesale, so there is no original element to carry the unknown `b` over to.
    let result = update(&extended_original(), &known_update());
    assert_eq!(result.items[0].a, "ni1");
    assert_eq!(result.items[0].b, "");
}

#[test]
fn unknown_enum_value_is_preserved_when_field_is_not_updated() {
    // The known schema cannot name KIND_C, but must carry it through a parse/serialize cycle
    let mut original = extended_original();
    original.kind = EnumOrUnknown::new(ext::Kind::KIND_C);
    let bytes = original.write_to_bytes().unwrap();
    let as_known = known::Record::parse_from_bytes(&bytes).unwrap();
    assert_eq!(as_known.kind.value(), 3);
    assert!(as_known.kind.enum_value().is_err());
    let reserialized = as_known.write_to_bytes().unwrap();
    let result = ext::Record::parse_from_bytes(&reserialized).unwrap();
    assert_eq!(result.kind.enum_value(), Ok(ext::Kind::KIND_C));
}

#[test]
fn unknown_enum_value_is_replaced_when_field_is_updated() {
    let mut original = extended_original();
    original.kind = EnumOrUnknown::new(ext::Kind::KIND_C);
    let result = update(&original, &known_update());
    assert_eq!(result.kind.enum_value(), Ok(ext::Kind::KIND_B));
}

#[test]
fn oneof_can_switch_between_known_variants() {
    let mut original = extended_original();
    original.payload = Some(ext::record::Payload::Text("text".into()));
    let mut new = known_update();
    new.payload = Some(known::record::Payload::Nested(known::Inner {
        a: "n".into(),
        ..Default::default()
    }));
    let result = update(&original, &new);
    assert_eq!(result.payload, Some(ext::record::Payload::Nested(inner("n", ""))));
}

#[test]
fn message_inside_oneof_keeps_its_unknown_fields() {
    let mut original = extended_original();
    original.payload = Some(ext::record::Payload::Nested(inner("old", "oneof b")));
    let mut new = known_update();
    new.payload = Some(known::record::Payload::Nested(known::Inner {
        a: "new".into(),
        ..Default::default()
    }));
    let result = update(&original, &new);
    assert_eq!(
        result.payload,
        Some(ext::record::Payload::Nested(inner("new", "oneof b")))
    );
}

#[test]
fn oneof_can_be_cleared() {
    let mut original = extended_original();
    original.payload = Some(ext::record::Payload::Text("text".into()));
    let result = update(&original, &known_update());
    assert_eq!(result.payload, None);
}

#[test]
fn unknown_oneof_variant_is_preserved_when_oneof_is_not_updated() {
    let mut original = extended_original();
    original.payload = Some(ext::record::Payload::Blob(vec![1, 2, 3]));
    let result = update(&original, &known_update());
    assert_eq!(result.payload, Some(ext::record::Payload::Blob(vec![1, 2, 3])));
}

#[test]
fn known_oneof_variant_does_not_override_unknown_one() {
    // KNOWN LIMITATION, pinned so it can't change unnoticed. The original holds a oneof variant that
    // only a newer build understands (kept as an unknown field). Setting a known variant on top
    // writes both to the wire, and on parse the unknown variant (serialized last) wins, so the
    // caller's change is silently lost. Fixing it needs the unknown variant numbers to be removed
    // explicitly, which can't be done generically.
    let mut original = extended_original();
    original.payload = Some(ext::record::Payload::Blob(vec![1, 2, 3]));
    let mut new = known_update();
    new.payload = Some(known::record::Payload::Text("text".into()));
    let result = update(&original, &new);
    assert_eq!(result.payload, Some(ext::record::Payload::Blob(vec![1, 2, 3])));
}

#[test]
fn update_is_idempotent() {
    let once = perform_update(&extended_original().write_to_bytes().unwrap(), &known_update());
    let twice = perform_update(&once, &known_update());
    // Compared parsed, as the order unknown fields are written in isn't stable
    assert_eq!(
        ext::Record::parse_from_bytes(&once).unwrap(),
        ext::Record::parse_from_bytes(&twice).unwrap()
    );
}

#[test]
fn update_on_data_without_unknown_fields_equals_plain_serialization() {
    let original = known::Record {
        title: "o".into(),
        tags: vec!["a".into(), "b".into()],
        ..Default::default()
    };
    let new = known_update();
    let updated = perform_update(&original.write_to_bytes().unwrap(), &new);
    assert_eq!(updated, new.write_to_bytes().unwrap());
}
