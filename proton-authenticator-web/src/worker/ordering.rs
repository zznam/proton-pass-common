use crate::entry::WasmAuthenticatorEntryModel;
use proton_authenticator::ordering::{EntryWithOrder, reorder_items};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Tsify, Deserialize, Serialize)]
pub struct AuthenticatorEntryWithOrder {
    pub entry: WasmAuthenticatorEntryModel,
    pub modify_time: i64,
    pub order: i32,
}

impl TryFrom<AuthenticatorEntryWithOrder> for EntryWithOrder {
    type Error = JsError;

    fn try_from(value: AuthenticatorEntryWithOrder) -> Result<Self, Self::Error> {
        let as_entry = value.entry.to_entry()?;
        Ok(Self {
            entry: as_entry,
            modify_time: value.modify_time,
            order: value.order,
        })
    }
}

impl From<EntryWithOrder> for AuthenticatorEntryWithOrder {
    fn from(value: EntryWithOrder) -> Self {
        Self {
            entry: WasmAuthenticatorEntryModel::from(value.entry),
            modify_time: value.modify_time,
            order: value.order,
        }
    }
}

#[wasm_bindgen]
pub fn sort_entries(
    local: Vec<Ts<AuthenticatorEntryWithOrder>>,
    remote: Vec<Ts<AuthenticatorEntryWithOrder>>,
) -> Result<Vec<Ts<AuthenticatorEntryWithOrder>>, JsError> {
    let mut local_mapped = vec![];
    for entry in local {
        local_mapped.push(EntryWithOrder::try_from(entry.to_rust()?)?);
    }
    let mut remote_mapped = vec![];
    for entry in remote {
        remote_mapped.push(EntryWithOrder::try_from(entry.to_rust()?)?);
    }

    let res = reorder_items(&local_mapped, &remote_mapped);

    let mut res_mapped = Vec::new();
    for entry in res {
        res_mapped.push(AuthenticatorEntryWithOrder::from(entry).into_ts()?);
    }

    Ok(res_mapped)
}
