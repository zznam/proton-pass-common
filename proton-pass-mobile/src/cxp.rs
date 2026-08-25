use proton_pass_common::cxf::{CxfExportInput, CxfImportResult};
use proton_pass_common::cxp::{
    CxpError, CxpExportHandler as CommonExportHandler, CxpExportRequest, CxpExportRequestSummary, CxpExportResponse,
    CxpImportHandler as CommonImportHandler,
};

#[derive(uniffi::Object)]
pub struct CxpImportHandler {
    inner: CommonImportHandler,
}

#[uniffi::export]
impl CxpImportHandler {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: CommonImportHandler::new(),
        }
    }

    pub fn create_export_request(&self, request: CxpExportRequest) -> Result<String, CxpError> {
        self.inner.create_export_request(request)
    }

    pub fn process_export_response(&self, encrypted_response: Vec<u8>) -> Result<CxfImportResult, CxpError> {
        self.inner.process_export_response(&encrypted_response)
    }
}

#[derive(uniffi::Object)]
pub struct CxpExportHandler {
    inner: CommonExportHandler,
}

#[uniffi::export]
impl CxpExportHandler {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: CommonExportHandler::new(),
        }
    }

    pub fn create_export_response(
        &self,
        request: String,
        export: CxfExportInput,
    ) -> Result<CxpExportResponse, CxpError> {
        self.inner.create_export_response(&request, export)
    }

    pub fn parse_export_request(&self, request: String) -> Result<CxpExportRequestSummary, CxpError> {
        self.inner.parse_export_request(&request)
    }
}
