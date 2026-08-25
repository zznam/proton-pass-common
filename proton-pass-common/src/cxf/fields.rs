use credential_exchange_format::{
    EditableField, EditableFieldConcealedString, EditableFieldCountryCode, EditableFieldDate, EditableFieldString,
    EditableFieldSubdivisionCode,
};

use super::ProtonExtension;

pub(crate) fn string_field(value: String) -> EditableField<EditableFieldString, ProtonExtension> {
    value.into()
}

pub(crate) fn opt_string_field(value: &str) -> Option<EditableField<EditableFieldString, ProtonExtension>> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string().into())
    }
}

pub(crate) fn concealed_field(value: String) -> EditableField<EditableFieldConcealedString, ProtonExtension> {
    value.into()
}

pub(crate) fn opt_concealed_field(value: &str) -> Option<EditableField<EditableFieldConcealedString, ProtonExtension>> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string().into())
    }
}

pub(crate) fn field_to_string(field: EditableField<EditableFieldString, ProtonExtension>) -> String {
    field.into()
}

pub(crate) fn opt_field_to_string(field: Option<EditableField<EditableFieldString, ProtonExtension>>) -> String {
    field.map(field_to_string).unwrap_or_default()
}

pub(crate) fn concealed_field_to_string(field: EditableField<EditableFieldConcealedString, ProtonExtension>) -> String {
    field.into()
}

pub(crate) fn opt_concealed_field_to_string(
    field: Option<EditableField<EditableFieldConcealedString, ProtonExtension>>,
) -> String {
    field.map(concealed_field_to_string).unwrap_or_default()
}

pub(crate) fn opt_territory_field(value: &str) -> Option<EditableField<EditableFieldSubdivisionCode, ProtonExtension>> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string().into())
    }
}

pub(crate) fn opt_territory_field_to_string(
    field: Option<EditableField<EditableFieldSubdivisionCode, ProtonExtension>>,
) -> String {
    field.map(String::from).unwrap_or_default()
}

pub(crate) fn opt_country_field(value: &str) -> Option<EditableField<EditableFieldCountryCode, ProtonExtension>> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string().into())
    }
}

pub(crate) fn opt_country_field_to_string(
    field: Option<EditableField<EditableFieldCountryCode, ProtonExtension>>,
) -> String {
    field.map(String::from).unwrap_or_default()
}

pub(crate) fn opt_date_field(value: &str) -> Option<EditableField<EditableFieldDate, ProtonExtension>> {
    let date = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()?;
    Some(EditableField {
        id: None,
        value: EditableFieldDate(date).into(),
        label: None,
        extensions: None,
    })
}

pub(crate) fn opt_date_field_to_string(field: Option<EditableField<EditableFieldDate, ProtonExtension>>) -> String {
    field
        .and_then(|f| f.value.into_expected().ok())
        .map(String::from)
        .unwrap_or_default()
}
