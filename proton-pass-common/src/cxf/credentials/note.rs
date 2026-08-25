use credential_exchange_format::{Credential, NoteCredential};

use crate::cxf::{
    CxfCredential, ProtonExtension,
    fields::{field_to_string, string_field},
};

pub(crate) fn note_text_to_credential(note: &str) -> CxfCredential {
    Credential::Note(Box::new(NoteCredential {
        content: string_field(note.to_string()),
    }))
}

pub(crate) fn credential_to_note_text(cred: &NoteCredential<ProtonExtension>) -> String {
    field_to_string(cred.content.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_round_trips() {
        let note = "hello world";
        let cred = note_text_to_credential(note);
        let Credential::Note(cred) = cred else {
            panic!("expected note credential")
        };
        assert_eq!(credential_to_note_text(&cred), note);
    }

    #[test]
    fn empty_note_round_trips() {
        let note = "";
        let cred = note_text_to_credential(note);
        let Credential::Note(cred) = cred else {
            panic!("expected note credential")
        };
        assert_eq!(credential_to_note_text(&cred), note);
    }
}
