mod image_types;

use image_types::WasmConvertImageError;
use proton_pass_common::image::{ConvertImageError as CommonConvertImageError, image_bytes_to_256_webp};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

impl From<CommonConvertImageError> for WasmConvertImageError {
    fn from(value: CommonConvertImageError) -> Self {
        match value {
            CommonConvertImageError::UnsupportedInputFormat => Self::unsupported_input_format(),
            CommonConvertImageError::Image(e) => Self::image(e.to_string()),
        }
    }
}

#[wasm_bindgen]
pub fn convert_image_to_256_webp(input: &[u8]) -> Result<Vec<u8>, JsValue> {
    image_bytes_to_256_webp(input).map_err(|e| match WasmConvertImageError::from(e).into_ts() {
        Ok(ts) => ts.js_value(),
        Err(serialize_err) => JsValue::from(JsError::new(&format!(
            "failed to serialize WasmConvertImageError: {serialize_err}"
        ))),
    })
}
