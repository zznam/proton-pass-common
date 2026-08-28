use credential_exchange_format::B64Url;
use proton_pass_types::{VaultData, VaultDisplayPreferences};
use rand::RngExt;

use super::CxfCollection;

pub(crate) fn generate_id() -> B64Url {
    let bytes: [u8; 16] = rand::rng().random();
    B64Url::from(bytes.to_vec())
}

pub(crate) fn generate_item_id(item_uuid: &str) -> B64Url {
    if item_uuid.is_empty() {
        generate_id()
    } else {
        B64Url::from(item_uuid.as_bytes())
    }
}

pub(crate) fn vault_to_collection(
    vault: &VaultData,
    id: B64Url,
    items: Vec<credential_exchange_format::LinkedItem>,
) -> CxfCollection {
    CxfCollection {
        id,
        creation_at: None,
        modified_at: None,
        title: vault.name.clone(),
        subtitle: (!vault.description.is_empty()).then(|| vault.description.clone()),
        items,
        sub_collections: None,
        extensions: None,
    }
}

pub(crate) fn collection_to_vault(collection: &CxfCollection) -> VaultData {
    VaultData {
        name: collection.title.clone(),
        description: collection.subtitle.clone().unwrap_or_default(),
        display_preferences: VaultDisplayPreferences::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_round_trips() {
        let vault = VaultData {
            name: "My vault".to_string(),
            description: "A description".to_string(),
            display_preferences: VaultDisplayPreferences::default(),
        };
        let collection = vault_to_collection(&vault, generate_id(), Vec::new());
        let back = collection_to_vault(&collection);
        assert_eq!(back, vault);
    }

    #[test]
    fn empty_description_round_trips_to_none_subtitle() {
        let vault = VaultData {
            name: "V".to_string(),
            description: String::new(),
            display_preferences: VaultDisplayPreferences::default(),
        };
        let collection = vault_to_collection(&vault, generate_id(), Vec::new());
        assert!(collection.subtitle.is_none());
        assert_eq!(collection_to_vault(&collection), vault);
    }

    #[test]
    fn item_id_is_deterministic_from_uuid() {
        let uuid = "11111111-1111-1111-1111-111111111111";
        let id1 = generate_item_id(uuid);
        let id2 = generate_item_id(uuid);
        assert_eq!(id1, id2);
    }

    #[test]
    fn empty_uuid_mints_random_id() {
        let id1 = generate_item_id("");
        let id2 = generate_item_id("");
        assert_ne!(id1, id2);
    }
}
