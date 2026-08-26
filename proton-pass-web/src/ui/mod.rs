use crate::ui::file::WasmFileGroup;

use creditcard::*;

use proton_pass_common::file::{
    get_file_group_from_mime_type, get_mime_type_from_content, get_mime_type_from_head_and_tail, sanitize_name,
};

#[cfg(feature = "experimental")]
use crate::ui::wifi::WasmWifiSecurity;
#[cfg(feature = "experimental")]
use login::WasmLogin;
#[cfg(feature = "experimental")]
use proton_pass_common::wifi::generate_wifi_uri;

use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

mod creditcard;
mod file;
mod totp;

#[cfg(feature = "experimental")]
mod login;
pub mod markdown;
#[cfg(feature = "experimental")]
mod wifi;

#[wasm_bindgen]
pub fn is_email_valid(email: String) -> bool {
    proton_pass_common::email::is_email_valid(&email)
}

#[wasm_bindgen]
pub fn validate_alias_prefix(prefix: String) -> Result<(), JsError> {
    match proton_pass_common::alias_prefix::validate_alias_prefix(&prefix) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(feature = "experimental")]
#[wasm_bindgen]
pub fn validate_login_obj(login: Ts<WasmLogin>) -> Result<(), JsError> {
    let login = login.to_rust()?;
    match proton_pass_common::login::validate_login(login.into()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[wasm_bindgen]
pub fn get_root_domain(input: String) -> Result<String, JsError> {
    Ok(proton_pass_common::domain::get_root_domain(&input)?)
}

#[wasm_bindgen]
pub fn get_domain(input: String) -> Result<String, JsError> {
    Ok(proton_pass_common::domain::get_domain(&input)?)
}

#[wasm_bindgen]
pub fn detect_credit_card_type(card_number: String) -> Result<Ts<WasmCreditCardType>, JsError> {
    let detector = CreditCardDetector::default();
    let detected = detector.detect(&card_number);
    let wasm_type: WasmCreditCardType = detected.into();
    Ok(wasm_type.into_ts()?)
}

#[wasm_bindgen]
pub fn file_group_from_mime_type(mime_type: String) -> Result<Ts<WasmFileGroup>, JsError> {
    Ok(WasmFileGroup::from(get_file_group_from_mime_type(&mime_type)).into_ts()?)
}

#[wasm_bindgen]
pub fn mime_type_from_content(content: js_sys::Uint8Array) -> String {
    let as_vec = content.to_vec();
    get_mime_type_from_content(&as_vec)
}

#[wasm_bindgen]
pub fn mime_type_from_content_head_tail(head: js_sys::Uint8Array, tail: js_sys::Uint8Array, size: u64) -> String {
    let head_bytes = head.to_vec();
    let tail_bytes = tail.to_vec();
    get_mime_type_from_head_and_tail(&head_bytes, &tail_bytes, size)
}

#[wasm_bindgen]
pub fn sanitize_filename(name: String, windows: bool) -> String {
    sanitize_name(&name, windows)
}

#[cfg(feature = "experimental")]
#[wasm_bindgen]
pub fn generate_wifi_svg_qr_code(
    ssid: String,
    password: String,
    security: Ts<WasmWifiSecurity>,
) -> Result<String, JsError> {
    let security = security.to_rust()?;
    let uri = generate_wifi_uri(&ssid, &password, security.into()).map_err(JsError::from)?;
    generate_svg_qr_code(uri)
}

#[cfg(feature = "experimental")]
#[wasm_bindgen]
pub fn generate_svg_qr_code(value: String) -> Result<String, JsError> {
    proton_pass_common::qr::generate_svg_qr_code(&value).map_err(|e| e.into())
}
