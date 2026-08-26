use proton_pass_common::share::{Share, visible_share_ids};
use tsify::Ts;
use wasm_bindgen::prelude::*;

// Re-export core types that now have wasm bindings

#[wasm_bindgen]
pub fn get_visible_shares(shares: Vec<Ts<Share>>, filter_hidden: bool) -> Result<Vec<String>, JsError> {
    let shares = shares.into_iter().map(|s| s.to_rust()).collect::<Result<Vec<_>, _>>()?;
    Ok(visible_share_ids(&shares, filter_hidden)
        .into_iter()
        .map(|s| s.to_string())
        .collect())
}
