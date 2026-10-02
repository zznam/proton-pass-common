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

use anyhow::{Context, Result};
use protobuf::MessageDyn;
use protobuf::MessageFull;
use protobuf::reflect::{RuntimeFieldType, RuntimeType};

/// Serializes `new` (which fully describes every field this build knows about) while keeping the
/// fields that `original` carries but this build doesn't know about, as written by a newer client.
///
/// Known fields always take the value from `new`: scalars, optionals, repeated fields, maps and
/// oneofs are replaced, so reverting a field to its default or removing it works. Unknown fields are
/// carried over from `original` at the top level and inside every singular embedded message.
///
/// Limitations:
///  - Unknown fields inside elements of repeated fields (or map values) are dropped, as there is no
///    reliable way to pair the original elements with the new ones.
///  - A oneof variant that this build doesn't know about is kept as an unknown field, so it will win
///    over a known variant set in `new`.
pub(crate) fn update_preserving_unknown<M: MessageFull>(original: &[u8], new: &M) -> Result<Vec<u8>> {
    let original = M::parse_from_bytes(original).context("Error decoding original message from proto")?;
    let mut updated = new.clone();
    carry_over_unknown_fields(&original, &mut updated);
    updated
        .write_to_bytes()
        .context("Error serializing updated message to proto")
}

fn carry_over_unknown_fields(original: &dyn MessageDyn, updated: &mut dyn MessageDyn) {
    *updated.mut_unknown_fields_dyn() = original.unknown_fields_dyn().clone();

    for field in updated.descriptor_dyn().fields() {
        let is_singular_message = matches!(
            field.runtime_field_type(),
            RuntimeFieldType::Singular(RuntimeType::Message(_))
        );
        if is_singular_message && field.has_field(original) && field.has_field(updated) {
            let original_nested = field.get_message(original);
            carry_over_unknown_fields(&*original_nested, field.mut_message(updated));
        }
    }
}
