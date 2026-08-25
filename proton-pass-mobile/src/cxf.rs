use proton_pass_common::cxf::{CxfError, CxfExportInput, CxfExportResult, CxfImportResult, export_cxf, import_cxf};

#[derive(uniffi::Object)]
pub struct CxfSerialization;

#[uniffi::export]
impl CxfSerialization {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn export(&self, input: CxfExportInput) -> Result<CxfExportResult, CxfError> {
        export_cxf(input)
    }

    pub fn import(&self, payload: String) -> Result<CxfImportResult, CxfError> {
        import_cxf(&payload)
    }
}
