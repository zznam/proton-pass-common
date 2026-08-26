use tsify::Ts;
use wasm_bindgen::prelude::*;

use proton_pass_common::username::UsernameGeneratorConfig;

#[wasm_bindgen]
pub fn generate_username(config: Ts<UsernameGeneratorConfig>) -> Result<String, JsError> {
    let config = config.to_rust()?;
    let mut generator = proton_pass_common::username::get_generator();
    generator.generate_username(&config).map_err(|e| e.into())
}
