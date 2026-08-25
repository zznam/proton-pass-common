use proton_pass_common::cxf::{CxfExportInput, CxfExportResult, CxfImportResult, export_cxf, import_cxf};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn cxf_export(input: CxfExportInput) -> Result<CxfExportResult, JsError> {
    export_cxf(input).map_err(|e| JsError::new(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn cxf_import(payload: String) -> Result<CxfImportResult, JsError> {
    import_cxf(&payload).map_err(|e| JsError::new(&format!("{:?}", e)))
}
