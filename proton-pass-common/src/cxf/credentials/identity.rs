use credential_exchange_format::{
    AddressCredential, Credential, CustomFieldsCredential, DriversLicenseCredential, EditableField,
    EditableFieldString, EditableFieldValue, IdentityDocumentCredential, PassportCredential, PersonNameCredential,
};
use proton_pass_types::{CustomSection, IdentityItem, ItemExtraField, ItemExtraFieldContent};

use super::custom;
use crate::cxf::{
    CxfCredential, CxfWarning, ProtonExtension,
    fields::{
        opt_country_field, opt_country_field_to_string, opt_date_field, opt_date_field_to_string, opt_string_field,
        opt_territory_field, opt_territory_field_to_string,
    },
};

const PERSON_NAME_SECTION: &str = "Person Name";
const DRIVERS_LICENSE_SECTION: &str = "Driver's License";
const PASSPORT_SECTION: &str = "Passport";
const IDENTITY_DOCUMENT_SECTION: &str = "Identity Document";

const KNOWN_CUSTOM_FIELDS: &[&str] = &[
    "email",
    "organization",
    "floor",
    "county",
    "website",
    "x_handle",
    "second_phone_number",
    "linkedin",
    "reddit",
    "facebook",
    "yahoo",
    "instagram",
    "company",
    "job_title",
    "personal_website",
    "work_phone_number",
    "work_email",
];

fn find_section<'a>(sections: &'a [CustomSection], title: &str) -> Option<&'a CustomSection> {
    sections.iter().find(|s| s.section_name == title)
}

fn find_field_value(section: Option<&CustomSection>, name: &str) -> String {
    section
        .and_then(|s| s.section_fields.iter().find(|f| f.name == name))
        .map(|f| f.value())
        .unwrap_or_default()
}

fn text_string_field(value: &str) -> Option<EditableField<EditableFieldString, ProtonExtension>> {
    opt_string_field(value)
}

fn text_extra_field(name: &str, value: String) -> Option<ItemExtraField> {
    if value.is_empty() {
        None
    } else {
        Some(ItemExtraField {
            name: name.to_string(),
            content: ItemExtraFieldContent::Text(value),
        })
    }
}

pub(crate) fn person_name_credential(item: &IdentityItem) -> Option<CxfCredential> {
    let extras = find_section(&item.extra_sections, PERSON_NAME_SECTION);
    let has_component = !item.first_name.is_empty() || !item.middle_name.is_empty() || !item.last_name.is_empty();
    if !has_component && extras.is_none() {
        return None;
    }

    Some(Credential::PersonName(Box::new(PersonNameCredential {
        title: text_string_field(&find_field_value(extras, "title")),
        given: opt_string_field(&item.first_name),
        given_informal: text_string_field(&find_field_value(extras, "given_informal")),
        given2: opt_string_field(&item.middle_name),
        surname_prefix: text_string_field(&find_field_value(extras, "surname_prefix")),
        surname: opt_string_field(&item.last_name),
        surname2: text_string_field(&find_field_value(extras, "surname2")),
        credentials: text_string_field(&find_field_value(extras, "credentials")),
        generation: text_string_field(&find_field_value(extras, "generation")),
    })))
}

pub(crate) fn address_credential(item: &IdentityItem) -> Option<CxfCredential> {
    if item.phone_number.is_empty()
        && item.street_address.is_empty()
        && item.zip_or_postal_code.is_empty()
        && item.city.is_empty()
        && item.state_or_province.is_empty()
        && item.country_or_region.is_empty()
    {
        return None;
    }

    Some(Credential::Address(Box::new(AddressCredential {
        street_address: opt_string_field(&item.street_address),
        postal_code: opt_string_field(&item.zip_or_postal_code),
        city: opt_string_field(&item.city),
        territory: opt_territory_field(&item.state_or_province),
        country: opt_country_field(&item.country_or_region),
        tel: opt_string_field(&item.phone_number),
    })))
}

pub(crate) fn drivers_license_credential(
    item: &IdentityItem,
    carry_full_name: bool,
    carry_shared: bool,
) -> Option<CxfCredential> {
    let extras = find_section(&item.extra_sections, DRIVERS_LICENSE_SECTION);
    if item.license_number.is_empty() && extras.is_none() && !carry_full_name && !carry_shared {
        return None;
    }

    Some(Credential::DriversLicense(Box::new(DriversLicenseCredential {
        full_name: carry_full_name
            .then(|| item.full_name.clone())
            .filter(|s| !s.is_empty())
            .and_then(|s| opt_string_field(&s)),
        birth_date: carry_shared.then(|| opt_date_field(&item.birthdate)).flatten(),
        issue_date: opt_date_field(&find_field_value(extras, "issue_date")),
        expiry_date: opt_date_field(&find_field_value(extras, "expiry_date")),
        issuing_authority: text_string_field(&find_field_value(extras, "issuing_authority")),
        territory: opt_territory_field(&find_field_value(extras, "territory")),
        country: opt_country_field(&find_field_value(extras, "country")),
        license_number: opt_string_field(&item.license_number),
        license_class: text_string_field(&find_field_value(extras, "license_class")),
    })))
}

pub(crate) fn passport_credential(
    item: &IdentityItem,
    carry_full_name: bool,
    carry_shared: bool,
) -> Option<CxfCredential> {
    let extras = find_section(&item.extra_sections, PASSPORT_SECTION);
    if item.passport_number.is_empty() && extras.is_none() && !carry_full_name && !carry_shared {
        return None;
    }

    Some(Credential::Passport(Box::new(PassportCredential {
        issuing_country: opt_country_field(&find_field_value(extras, "issuing_country")),
        passport_type: text_string_field(&find_field_value(extras, "passport_type")),
        passport_number: opt_string_field(&item.passport_number),
        national_identification_number: text_string_field(&find_field_value(extras, "national_identification_number")),
        nationality: text_string_field(&find_field_value(extras, "nationality")),
        full_name: carry_full_name
            .then(|| item.full_name.clone())
            .filter(|s| !s.is_empty())
            .and_then(|s| opt_string_field(&s)),
        birth_date: carry_shared.then(|| opt_date_field(&item.birthdate)).flatten(),
        birth_place: text_string_field(&find_field_value(extras, "birth_place")),
        sex: carry_shared.then(|| opt_string_field(&item.gender)).flatten(),
        issue_date: opt_date_field(&find_field_value(extras, "issue_date")),
        expiry_date: opt_date_field(&find_field_value(extras, "expiry_date")),
        issuing_authority: text_string_field(&find_field_value(extras, "issuing_authority")),
    })))
}

pub(crate) fn identity_document_credential(
    item: &IdentityItem,
    carry_full_name: bool,
    carry_shared: bool,
    force: bool,
) -> Option<CxfCredential> {
    let extras = find_section(&item.extra_sections, IDENTITY_DOCUMENT_SECTION);
    if item.social_security_number.is_empty()
        && item.gender.is_empty()
        && extras.is_none()
        && !carry_full_name
        && !carry_shared
        && !force
    {
        return None;
    }

    Some(Credential::IdentityDocument(Box::new(IdentityDocumentCredential {
        issuing_country: opt_country_field(&find_field_value(extras, "issuing_country")),
        document_number: text_string_field(&find_field_value(extras, "document_number")),
        identification_number: opt_string_field(&item.social_security_number),
        nationality: text_string_field(&find_field_value(extras, "nationality")),
        full_name: carry_full_name
            .then(|| item.full_name.clone())
            .filter(|s| !s.is_empty())
            .and_then(|s| opt_string_field(&s)),
        birth_date: carry_shared.then(|| opt_date_field(&item.birthdate)).flatten(),
        birth_place: text_string_field(&find_field_value(extras, "birth_place")),
        sex: carry_shared.then(|| opt_string_field(&item.gender)).flatten(),
        issue_date: opt_date_field(&find_field_value(extras, "issue_date")),
        expiry_date: opt_date_field(&find_field_value(extras, "expiry_date")),
        issuing_authority: text_string_field(&find_field_value(extras, "issuing_authority")),
    })))
}

fn push_known(fields: &mut Vec<EditableFieldValue<ProtonExtension>>, name: &str, value: &str) {
    if !value.is_empty() {
        fields.push(EditableFieldValue::String(EditableField {
            id: None,
            value: EditableFieldString(value.to_string()).into(),
            label: Some(name.to_string()),
            extensions: None,
        }));
    }
}

pub(crate) fn unmapped_fields_credential(item: &IdentityItem) -> Option<CxfCredential> {
    let mut fields = Vec::new();
    push_known(&mut fields, "email", &item.email);
    push_known(&mut fields, "organization", &item.organization);
    push_known(&mut fields, "floor", &item.floor);
    push_known(&mut fields, "county", &item.county);
    push_known(&mut fields, "website", &item.website);
    push_known(&mut fields, "x_handle", &item.x_handle);
    push_known(&mut fields, "second_phone_number", &item.second_phone_number);
    push_known(&mut fields, "linkedin", &item.linkedin);
    push_known(&mut fields, "reddit", &item.reddit);
    push_known(&mut fields, "facebook", &item.facebook);
    push_known(&mut fields, "yahoo", &item.yahoo);
    push_known(&mut fields, "instagram", &item.instagram);
    push_known(&mut fields, "company", &item.company);
    push_known(&mut fields, "job_title", &item.job_title);
    push_known(&mut fields, "personal_website", &item.personal_website);
    push_known(&mut fields, "work_phone_number", &item.work_phone_number);
    push_known(&mut fields, "work_email", &item.work_email);

    for f in item
        .extra_personal_details
        .iter()
        .chain(&item.extra_address_details)
        .chain(&item.extra_contact_details)
        .chain(&item.extra_work_details)
    {
        if let Some(v) = custom::extra_field_to_editable_value(f) {
            fields.push(v);
        }
    }

    if fields.is_empty() {
        return None;
    }
    Some(Credential::CustomFields(Box::new(CustomFieldsCredential {
        id: None,
        label: None,
        fields,
        extensions: Vec::new(),
    })))
}

pub(crate) fn identity_to_credentials(item: &IdentityItem) -> Vec<CxfCredential> {
    let has_person_name = !item.first_name.is_empty() || !item.middle_name.is_empty() || !item.last_name.is_empty();
    let has_drivers_license =
        !item.license_number.is_empty() || find_section(&item.extra_sections, DRIVERS_LICENSE_SECTION).is_some();
    let has_passport =
        !item.passport_number.is_empty() || find_section(&item.extra_sections, PASSPORT_SECTION).is_some();

    let full_name_carrier_is_dl = has_drivers_license;
    let full_name_carrier_is_passport = !full_name_carrier_is_dl && has_passport;
    let needs_forced_document = !item.full_name.is_empty() && !has_person_name && !has_drivers_license && !has_passport;
    let full_name_carrier_is_document = !full_name_carrier_is_dl && !full_name_carrier_is_passport;

    let has_shared_fields = !item.birthdate.is_empty() || !item.gender.is_empty();

    let mut credentials = Vec::new();
    if let Some(c) = person_name_credential(item) {
        credentials.push(c);
    }
    if let Some(c) = address_credential(item) {
        credentials.push(c);
    }
    if let Some(c) = drivers_license_credential(
        item,
        full_name_carrier_is_dl,
        has_shared_fields && full_name_carrier_is_dl,
    ) {
        credentials.push(c);
    }
    if let Some(c) = passport_credential(
        item,
        full_name_carrier_is_passport,
        has_shared_fields && full_name_carrier_is_passport,
    ) {
        credentials.push(c);
    }
    if let Some(c) = identity_document_credential(
        item,
        full_name_carrier_is_document,
        has_shared_fields && full_name_carrier_is_document,
        needs_forced_document,
    ) {
        credentials.push(c);
    }
    if let Some(c) = unmapped_fields_credential(item) {
        credentials.push(c);
    }

    for section in &item.extra_sections {
        if ![
            PERSON_NAME_SECTION,
            DRIVERS_LICENSE_SECTION,
            PASSPORT_SECTION,
            IDENTITY_DOCUMENT_SECTION,
        ]
        .contains(&section.section_name.as_str())
        {
            credentials.push(custom::custom_section_to_credential(section));
        }
    }

    credentials
}

pub(crate) fn credentials_to_identity(
    credentials: &[CxfCredential],
    item_title: Option<&str>,
    warnings: &mut Vec<CxfWarning>,
) -> IdentityItem {
    let mut identity = IdentityItem {
        full_name: String::new(),
        email: String::new(),
        phone_number: String::new(),
        first_name: String::new(),
        middle_name: String::new(),
        last_name: String::new(),
        birthdate: String::new(),
        gender: String::new(),
        extra_personal_details: Vec::new(),
        organization: String::new(),
        street_address: String::new(),
        zip_or_postal_code: String::new(),
        city: String::new(),
        state_or_province: String::new(),
        country_or_region: String::new(),
        floor: String::new(),
        county: String::new(),
        extra_address_details: Vec::new(),
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
        extra_contact_details: Vec::new(),
        company: String::new(),
        job_title: String::new(),
        personal_website: String::new(),
        work_phone_number: String::new(),
        work_email: String::new(),
        extra_work_details: Vec::new(),
        extra_sections: Vec::new(),
    };

    let mut person_name_extra_fields = Vec::new();
    let mut drivers_license_extra_fields = Vec::new();
    let mut passport_extra_fields = Vec::new();
    let mut identity_document_extra_fields = Vec::new();
    let mut unmatched_custom_fields = Vec::new();

    for cred in credentials {
        match cred {
            Credential::PersonName(c) => {
                identity.first_name = c.given.clone().map(String::from).unwrap_or_default();
                identity.middle_name = c.given2.clone().map(String::from).unwrap_or_default();
                identity.last_name = c.surname.clone().map(String::from).unwrap_or_default();
                if identity.full_name.is_empty() {
                    let joined = [&identity.first_name, &identity.middle_name, &identity.last_name]
                        .into_iter()
                        .filter(|s| !s.is_empty())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !joined.is_empty() {
                        identity.full_name = joined;
                    }
                }
                person_name_extra_fields.extend(
                    [
                        text_extra_field("title", c.title.clone().map(String::from).unwrap_or_default()),
                        text_extra_field(
                            "given_informal",
                            c.given_informal.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field(
                            "surname_prefix",
                            c.surname_prefix.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field("surname2", c.surname2.clone().map(String::from).unwrap_or_default()),
                        text_extra_field(
                            "credentials",
                            c.credentials.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field("generation", c.generation.clone().map(String::from).unwrap_or_default()),
                    ]
                    .into_iter()
                    .flatten(),
                );
            }
            Credential::Address(c) => {
                identity.street_address = c.street_address.clone().map(String::from).unwrap_or_default();
                identity.zip_or_postal_code = c.postal_code.clone().map(String::from).unwrap_or_default();
                identity.city = c.city.clone().map(String::from).unwrap_or_default();
                identity.state_or_province = opt_territory_field_to_string(c.territory.clone());
                identity.country_or_region = opt_country_field_to_string(c.country.clone());
                identity.phone_number = c.tel.clone().map(String::from).unwrap_or_default();
            }
            Credential::DriversLicense(c) => {
                if identity.full_name.is_empty() {
                    identity.full_name = c.full_name.clone().map(String::from).unwrap_or_default();
                }
                if identity.birthdate.is_empty() {
                    identity.birthdate = opt_date_field_to_string(c.birth_date.clone());
                }
                identity.license_number = c.license_number.clone().map(String::from).unwrap_or_default();
                drivers_license_extra_fields.extend(
                    [
                        text_extra_field("issue_date", opt_date_field_to_string(c.issue_date.clone())),
                        text_extra_field("expiry_date", opt_date_field_to_string(c.expiry_date.clone())),
                        text_extra_field(
                            "issuing_authority",
                            c.issuing_authority.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field("territory", opt_territory_field_to_string(c.territory.clone())),
                        text_extra_field("country", opt_country_field_to_string(c.country.clone())),
                        text_extra_field(
                            "license_class",
                            c.license_class.clone().map(String::from).unwrap_or_default(),
                        ),
                    ]
                    .into_iter()
                    .flatten(),
                );
            }
            Credential::Passport(c) => {
                if identity.full_name.is_empty() {
                    identity.full_name = c.full_name.clone().map(String::from).unwrap_or_default();
                }
                if identity.birthdate.is_empty() {
                    identity.birthdate = opt_date_field_to_string(c.birth_date.clone());
                }
                if identity.gender.is_empty() {
                    identity.gender = c.sex.clone().map(String::from).unwrap_or_default();
                }
                identity.passport_number = c.passport_number.clone().map(String::from).unwrap_or_default();
                passport_extra_fields.extend(
                    [
                        text_extra_field(
                            "issuing_country",
                            opt_country_field_to_string(c.issuing_country.clone()),
                        ),
                        text_extra_field(
                            "passport_type",
                            c.passport_type.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field(
                            "national_identification_number",
                            c.national_identification_number
                                .clone()
                                .map(String::from)
                                .unwrap_or_default(),
                        ),
                        text_extra_field(
                            "nationality",
                            c.nationality.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field(
                            "birth_place",
                            c.birth_place.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field("issue_date", opt_date_field_to_string(c.issue_date.clone())),
                        text_extra_field("expiry_date", opt_date_field_to_string(c.expiry_date.clone())),
                        text_extra_field(
                            "issuing_authority",
                            c.issuing_authority.clone().map(String::from).unwrap_or_default(),
                        ),
                    ]
                    .into_iter()
                    .flatten(),
                );
            }
            Credential::IdentityDocument(c) => {
                if identity.full_name.is_empty() {
                    identity.full_name = c.full_name.clone().map(String::from).unwrap_or_default();
                }
                if identity.birthdate.is_empty() {
                    identity.birthdate = opt_date_field_to_string(c.birth_date.clone());
                }
                if identity.gender.is_empty() {
                    identity.gender = c.sex.clone().map(String::from).unwrap_or_default();
                }
                let document_number = c.document_number.clone().map(String::from).unwrap_or_default();
                if document_number.is_empty() {
                    identity.social_security_number =
                        c.identification_number.clone().map(String::from).unwrap_or_default();
                }
                identity_document_extra_fields.extend(
                    [
                        text_extra_field(
                            "issuing_country",
                            opt_country_field_to_string(c.issuing_country.clone()),
                        ),
                        text_extra_field("document_number", document_number),
                        text_extra_field(
                            "nationality",
                            c.nationality.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field(
                            "birth_place",
                            c.birth_place.clone().map(String::from).unwrap_or_default(),
                        ),
                        text_extra_field("issue_date", opt_date_field_to_string(c.issue_date.clone())),
                        text_extra_field("expiry_date", opt_date_field_to_string(c.expiry_date.clone())),
                        text_extra_field(
                            "issuing_authority",
                            c.issuing_authority.clone().map(String::from).unwrap_or_default(),
                        ),
                    ]
                    .into_iter()
                    .flatten(),
                );
            }
            Credential::CustomFields(cf) if cf.label.is_none() => {
                for field in &cf.fields {
                    let EditableFieldValue::String(f) = field else {
                        unmatched_custom_fields
                            .push(custom::editable_value_to_extra_field(field, item_title, warnings));
                        continue;
                    };
                    let label = f.label.clone().unwrap_or_default();
                    let value: String = f.value.clone().into();
                    if !KNOWN_CUSTOM_FIELDS.contains(&label.as_str()) {
                        unmatched_custom_fields.push(ItemExtraField {
                            name: label,
                            content: ItemExtraFieldContent::Text(value),
                        });
                        continue;
                    }
                    match label.as_str() {
                        "email" => identity.email = value,
                        "organization" => identity.organization = value,
                        "floor" => identity.floor = value,
                        "county" => identity.county = value,
                        "website" => identity.website = value,
                        "x_handle" => identity.x_handle = value,
                        "second_phone_number" => identity.second_phone_number = value,
                        "linkedin" => identity.linkedin = value,
                        "reddit" => identity.reddit = value,
                        "facebook" => identity.facebook = value,
                        "yahoo" => identity.yahoo = value,
                        "instagram" => identity.instagram = value,
                        "company" => identity.company = value,
                        "job_title" => identity.job_title = value,
                        "personal_website" => identity.personal_website = value,
                        "work_phone_number" => identity.work_phone_number = value,
                        "work_email" => identity.work_email = value,
                        _ => unreachable!("filtered by KNOWN_CUSTOM_FIELDS above"),
                    }
                }
            }
            Credential::CustomFields(cf) => {
                identity
                    .extra_sections
                    .push(custom::credential_to_custom_section(cf, item_title, warnings));
            }
            _ => {}
        }
    }

    if !person_name_extra_fields.is_empty() {
        identity.extra_sections.push(CustomSection {
            section_name: PERSON_NAME_SECTION.to_string(),
            section_fields: person_name_extra_fields,
        });
    }
    if !drivers_license_extra_fields.is_empty() {
        identity.extra_sections.push(CustomSection {
            section_name: DRIVERS_LICENSE_SECTION.to_string(),
            section_fields: drivers_license_extra_fields,
        });
    }
    if !passport_extra_fields.is_empty() {
        identity.extra_sections.push(CustomSection {
            section_name: PASSPORT_SECTION.to_string(),
            section_fields: passport_extra_fields,
        });
    }
    if !identity_document_extra_fields.is_empty() {
        identity.extra_sections.push(CustomSection {
            section_name: IDENTITY_DOCUMENT_SECTION.to_string(),
            section_fields: identity_document_extra_fields,
        });
    }
    if !unmatched_custom_fields.is_empty() {
        identity.extra_sections.push(CustomSection {
            section_name: "Custom Fields".to_string(),
            section_fields: unmatched_custom_fields,
        });
    }

    identity
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_identity() -> IdentityItem {
        IdentityItem {
            full_name: String::new(),
            email: String::new(),
            phone_number: String::new(),
            first_name: String::new(),
            middle_name: String::new(),
            last_name: String::new(),
            birthdate: String::new(),
            gender: String::new(),
            extra_personal_details: Vec::new(),
            organization: String::new(),
            street_address: String::new(),
            zip_or_postal_code: String::new(),
            city: String::new(),
            state_or_province: String::new(),
            country_or_region: String::new(),
            floor: String::new(),
            county: String::new(),
            extra_address_details: Vec::new(),
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
            extra_contact_details: Vec::new(),
            company: String::new(),
            job_title: String::new(),
            personal_website: String::new(),
            work_phone_number: String::new(),
            work_email: String::new(),
            extra_work_details: Vec::new(),
            extra_sections: Vec::new(),
        }
    }

    #[test]
    fn person_name_round_trips() {
        let first_name = "Jane";
        let middle_name = "Q";
        let last_name = "Doe";
        let item = IdentityItem {
            first_name: first_name.to_string(),
            middle_name: middle_name.to_string(),
            last_name: last_name.to_string(),
            ..empty_identity()
        };
        let creds = identity_to_credentials(&item);
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, None, &mut warnings);
        assert_eq!(back.first_name, first_name);
        assert_eq!(back.middle_name, middle_name);
        assert_eq!(back.last_name, last_name);
        assert_eq!(back.full_name, format!("{first_name} {middle_name} {last_name}"));
    }

    #[test]
    fn address_round_trips() {
        let phone_number = "123";
        let street_address = "1 Main St";
        let zip_or_postal_code = "12345";
        let city = "Springfield";
        let state_or_province = "CA";
        let country_or_region = "US";
        let item = IdentityItem {
            phone_number: phone_number.to_string(),
            street_address: street_address.to_string(),
            zip_or_postal_code: zip_or_postal_code.to_string(),
            city: city.to_string(),
            state_or_province: state_or_province.to_string(),
            country_or_region: country_or_region.to_string(),
            ..empty_identity()
        };
        let creds = identity_to_credentials(&item);
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, None, &mut warnings);
        assert_eq!(back.phone_number, phone_number);
        assert_eq!(back.street_address, street_address);
        assert_eq!(back.zip_or_postal_code, zip_or_postal_code);
        assert_eq!(back.city, city);
        assert_eq!(back.state_or_province, state_or_province);
        assert_eq!(back.country_or_region, country_or_region);
    }

    #[test]
    fn full_name_falls_back_to_document_carrier_when_no_name_components() {
        let full_name = "Just A Name";
        let item = IdentityItem {
            full_name: full_name.to_string(),
            ..empty_identity()
        };
        let creds = identity_to_credentials(&item);
        assert!(creds.iter().any(|c| matches!(c, Credential::IdentityDocument(_))));
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, None, &mut warnings);
        assert_eq!(back.full_name, full_name);
    }

    #[test]
    fn drivers_license_round_trips_with_extras() {
        let license_number = "D1234";
        let birthdate = "1990-01-02";
        let item = IdentityItem {
            license_number: license_number.to_string(),
            birthdate: birthdate.to_string(),
            ..empty_identity()
        };
        let creds = identity_to_credentials(&item);
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, None, &mut warnings);
        assert_eq!(back.license_number, license_number);
        assert_eq!(back.birthdate, birthdate);
    }

    #[test]
    fn passport_round_trips() {
        let passport_number = "P1234";
        let gender = "F";
        let item = IdentityItem {
            passport_number: passport_number.to_string(),
            gender: gender.to_string(),
            ..empty_identity()
        };
        let creds = identity_to_credentials(&item);
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, None, &mut warnings);
        assert_eq!(back.passport_number, passport_number);
        assert_eq!(back.gender, gender);
    }

    #[test]
    fn ssn_maps_to_identification_number_only_without_document_number() {
        let social_security_number = "123-45-6789";
        let item = IdentityItem {
            social_security_number: social_security_number.to_string(),
            ..empty_identity()
        };
        let creds = identity_to_credentials(&item);
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, None, &mut warnings);
        assert_eq!(back.social_security_number, social_security_number);
    }

    #[test]
    fn document_number_present_prevents_ssn_mapping() {
        let cred = Credential::IdentityDocument(Box::new(IdentityDocumentCredential {
            issuing_country: None,
            document_number: opt_string_field("DOC1"),
            identification_number: opt_string_field("999-99-9999"),
            nationality: None,
            full_name: None,
            birth_date: None,
            birth_place: None,
            sex: None,
            issue_date: None,
            expiry_date: None,
            issuing_authority: None,
        }));
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&[cred], None, &mut warnings);
        assert!(back.social_security_number.is_empty());
        let section = back
            .extra_sections
            .iter()
            .find(|s| s.section_name == IDENTITY_DOCUMENT_SECTION)
            .expect("identity document section preserved");
        assert!(section.section_fields.iter().any(|f| f.name == "document_number"));
    }

    #[test]
    fn unmapped_pass_fields_round_trip_via_custom_fields_credential() {
        let organization = "Acme";
        let x_handle = "@jane";
        let email = "jane@example.com";
        let item = IdentityItem {
            organization: organization.to_string(),
            x_handle: x_handle.to_string(),
            email: email.to_string(),
            ..empty_identity()
        };
        let creds = identity_to_credentials(&item);
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, None, &mut warnings);
        assert_eq!(back.organization, organization);
        assert_eq!(back.x_handle, x_handle);
        assert_eq!(back.email, email);
    }

    #[test]
    fn unknown_cxf_field_becomes_custom_fields_section() {
        let section_name = "Some Foreign Section";
        let field_name = "foo";
        let cred = Credential::CustomFields(Box::new(CustomFieldsCredential {
            id: None,
            label: Some(section_name.to_string()),
            fields: vec![EditableFieldValue::String(EditableField {
                id: None,
                value: EditableFieldString("bar".to_string()).into(),
                label: Some(field_name.to_string()),
                extensions: None,
            })],
            extensions: Vec::new(),
        }));
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&[cred], None, &mut warnings);
        let section = back
            .extra_sections
            .iter()
            .find(|s| s.section_name == section_name)
            .expect("foreign labelled section preserved");
        assert!(section.section_fields.iter().any(|f| f.name == field_name));
    }

    #[test]
    fn full_identity_round_trip_fixture() {
        let item = IdentityItem {
            full_name: "Jane Q Doe".to_string(),
            email: "jane@example.com".to_string(),
            phone_number: "555-1234".to_string(),
            first_name: "Jane".to_string(),
            middle_name: "Q".to_string(),
            last_name: "Doe".to_string(),
            birthdate: "1990-01-02".to_string(),
            gender: "F".to_string(),
            organization: "Acme Corp".to_string(),
            street_address: "1 Main St".to_string(),
            zip_or_postal_code: "12345".to_string(),
            city: "Springfield".to_string(),
            state_or_province: "CA".to_string(),
            country_or_region: "US".to_string(),
            social_security_number: "123-45-6789".to_string(),
            passport_number: "P1234567".to_string(),
            license_number: "D7654321".to_string(),
            website: "https://jane.example".to_string(),
            company: "Acme Corp".to_string(),
            ..empty_identity()
        };

        let creds = identity_to_credentials(&item);
        let mut warnings = Vec::new();
        let back = credentials_to_identity(&creds, Some("Identity"), &mut warnings);

        assert_eq!(back.first_name, item.first_name);
        assert_eq!(back.last_name, item.last_name);
        assert_eq!(back.email, item.email);
        assert_eq!(back.phone_number, item.phone_number);
        assert_eq!(back.street_address, item.street_address);
        assert_eq!(back.city, item.city);
        assert_eq!(back.social_security_number, item.social_security_number);
        assert_eq!(back.passport_number, item.passport_number);
        assert_eq!(back.license_number, item.license_number);
        assert_eq!(back.organization, item.organization);
        assert_eq!(back.website, item.website);
        assert_eq!(back.company, item.company);
        assert_eq!(back.birthdate, item.birthdate);
    }
}
