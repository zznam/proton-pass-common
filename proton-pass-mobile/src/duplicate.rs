use proton_pass_common::duplicate::{DuplicateItemGroup, ItemForDuplicateDetection, find_duplicate_items};

#[derive(uniffi::Object)]
pub struct DuplicateItemDetector;

#[uniffi::export]
impl DuplicateItemDetector {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn find_duplicates(&self, items: Vec<ItemForDuplicateDetection>) -> Vec<DuplicateItemGroup> {
        find_duplicate_items(items)
    }
}
