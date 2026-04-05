use crate::state;
use crate::storage::storable::smtp::StorableEmail;
use internet_identity_interface::internet_identity::types::smtp::{
    validate_envelope_only, SmtpRequest, SmtpResponse, ValidatedSmtpRequest,
};

pub fn handle_smtp_request(request: SmtpRequest) -> SmtpResponse {
    let validated: ValidatedSmtpRequest = match request.try_into() {
        Ok(v) => v,
        Err(response) => return response,
    };

    let email = StorableEmail {
        sender: validated.sender,
        recipient: validated.recipient.clone(),
        subject: validated.subject,
        body: validated.body,
    };

    state::storage_borrow_mut(|storage| {
        storage.store_email(validated.recipient, email);
    });

    SmtpResponse::Ok {}
}

pub fn handle_smtp_request_validate(request: SmtpRequest) -> SmtpResponse {
    // If a full message is present, run full validation
    if request.message.is_some() {
        return match ValidatedSmtpRequest::try_from(request) {
            Ok(_) => SmtpResponse::Ok {},
            Err(response) => response,
        };
    }

    // Otherwise validate just the envelope (and whatever else is present)
    match validate_envelope_only(&request) {
        Ok(()) => SmtpResponse::Ok {},
        Err(response) => response,
    }
}
