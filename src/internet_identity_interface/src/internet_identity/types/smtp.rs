use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;

// --- Bounds ---

pub const MAX_EMAIL_USER_BYTES: usize = 64;
pub const MAX_EMAIL_DOMAIN_BYTES: usize = 255;
pub const MAX_SUBJECT_BYTES: usize = 256;
pub const MAX_BODY_BYTES: usize = 5_000;
pub const MAX_HEADERS: usize = 10;
pub const MAX_HEADER_NAME_BYTES: usize = 256;
pub const MAX_HEADER_VALUE_BYTES: usize = 8_192;
pub const MAX_EMAILS_PER_USER: usize = 10;

pub const ACCEPTED_DOMAIN: &str = "id.ai";

// --- SMTP error codes ---

const SMTP_ERR_MAILBOX_UNAVAILABLE: u64 = 550;
const SMTP_ERR_SYNTAX_ERROR: u64 = 555;

// --- API types (Candid) ---

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpMessage {
    pub headers: Vec<SmtpHeader>,
    pub body: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpAddress {
    pub user: String,
    pub domain: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpEnvelope {
    pub from: SmtpAddress,
    pub to: SmtpAddress,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpRequest {
    pub message: Option<SmtpMessage>,
    pub envelope: Option<SmtpEnvelope>,
    pub gateway_flags: Option<Vec<String>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpRequestError {
    pub code: u64,
    pub message: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum SmtpResponse {
    Ok {},
    Err(SmtpRequestError),
}

// --- Postbox query types ---

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct PostboxEmail {
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
}

// --- Validated internal types ---

#[derive(Clone, Debug)]
pub struct ValidatedSmtpRequest {
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
}

// --- Helpers ---

fn smtp_err(code: u64, message: impl Into<String>) -> SmtpResponse {
    SmtpResponse::Err(SmtpRequestError {
        code,
        message: message.into(),
    })
}

fn format_address(addr: &SmtpAddress) -> String {
    format!("{}@{}", addr.user, addr.domain)
}

fn validate_address_bounds(addr: &SmtpAddress, label: &str) -> Result<(), SmtpResponse> {
    if addr.user.len() > MAX_EMAIL_USER_BYTES {
        return Err(smtp_err(
            SMTP_ERR_SYNTAX_ERROR,
            format!("{label} user part exceeds {MAX_EMAIL_USER_BYTES} bytes"),
        ));
    }
    if addr.domain.len() > MAX_EMAIL_DOMAIN_BYTES {
        return Err(smtp_err(
            SMTP_ERR_SYNTAX_ERROR,
            format!("{label} domain exceeds {MAX_EMAIL_DOMAIN_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_envelope(envelope: &SmtpEnvelope) -> Result<(), SmtpResponse> {
    validate_address_bounds(&envelope.from, "Sender")?;
    validate_address_bounds(&envelope.to, "Recipient")?;

    if !envelope.to.domain.eq_ignore_ascii_case(ACCEPTED_DOMAIN) {
        return Err(smtp_err(
            SMTP_ERR_MAILBOX_UNAVAILABLE,
            format!("Relay not permitted: domain must be {ACCEPTED_DOMAIN}"),
        ));
    }

    envelope.to.user.parse::<u64>().map_err(|_| {
        smtp_err(
            SMTP_ERR_MAILBOX_UNAVAILABLE,
            "Recipient user must be a valid anchor number",
        )
    })?;

    Ok(())
}

fn validate_message(message: &SmtpMessage) -> Result<(), SmtpResponse> {
    if message.headers.len() > MAX_HEADERS {
        return Err(smtp_err(
            SMTP_ERR_SYNTAX_ERROR,
            format!(
                "Too many headers: {} (max {MAX_HEADERS})",
                message.headers.len()
            ),
        ));
    }

    for header in &message.headers {
        if header.name.len() > MAX_HEADER_NAME_BYTES {
            return Err(smtp_err(
                SMTP_ERR_SYNTAX_ERROR,
                format!("Header name exceeds {MAX_HEADER_NAME_BYTES} bytes"),
            ));
        }
        if header.value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(smtp_err(
                SMTP_ERR_SYNTAX_ERROR,
                format!(
                    "Header '{}' value exceeds {MAX_HEADER_VALUE_BYTES} bytes",
                    header.name
                ),
            ));
        }
    }

    if message.body.len() > MAX_BODY_BYTES {
        return Err(smtp_err(
            SMTP_ERR_SYNTAX_ERROR,
            format!(
                "Body size {} exceeds limit of {MAX_BODY_BYTES} bytes",
                message.body.len()
            ),
        ));
    }

    Ok(())
}

fn extract_subject(headers: &[SmtpHeader]) -> String {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("subject"))
        .map(|h| {
            let mut s = h.value.clone();
            s.truncate(MAX_SUBJECT_BYTES);
            s
        })
        .unwrap_or_default()
}

// --- TryFrom ---

impl TryFrom<SmtpRequest> for ValidatedSmtpRequest {
    type Error = SmtpResponse;

    fn try_from(request: SmtpRequest) -> Result<Self, Self::Error> {
        let envelope = request
            .envelope
            .as_ref()
            .ok_or_else(|| smtp_err(SMTP_ERR_SYNTAX_ERROR, "Missing envelope"))?;

        validate_envelope(envelope)?;

        let message = request
            .message
            .as_ref()
            .ok_or_else(|| smtp_err(SMTP_ERR_SYNTAX_ERROR, "Missing message"))?;

        validate_message(message)?;

        let body = String::from_utf8_lossy(&message.body).into_owned();

        Ok(ValidatedSmtpRequest {
            sender: format_address(&envelope.from),
            recipient: format_address(&envelope.to),
            subject: extract_subject(&message.headers),
            body,
        })
    }
}

/// Validates only the envelope portion of an SMTP request.
/// Used by `smtp_request_validate` when no message is present.
pub fn validate_envelope_only(request: &SmtpRequest) -> Result<(), SmtpResponse> {
    let envelope = request
        .envelope
        .as_ref()
        .ok_or_else(|| smtp_err(SMTP_ERR_SYNTAX_ERROR, "Missing envelope"))?;

    validate_envelope(envelope)?;

    if let Some(message) = &request.message {
        validate_message(message)?;
    }

    Ok(())
}
