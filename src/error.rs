//! Typed HTTP errors for the Drive/bridge/VPN REST calls.
//!
//! Every failing API call in this crate still returns [`anyhow::Error`] — no
//! public signature changes — but the error inside it is now an [`ApiError`]
//! carrying the upstream status code, the raw body and the server-provided
//! detail message, instead of a flattened string. A caller that only prints
//! the error sees the same text as before; a caller that needs the status can
//! recover it with `err.downcast_ref::<ApiError>()`.
//!
//! The motivating consumer is a server front-end: a WebDAV/SFTP/FUSE backend
//! built on this crate can map the upstream status straight onto its own
//! response (a Drive 404/403/507 reaches the client as 404/403/507 instead of
//! a blanket 500), which is what the official Node CLI does in its WebDAV
//! error middleware.

use reqwest::StatusCode;
use serde_json::Value;
use std::fmt;

/// A non-success HTTP response from one of Internxt's REST APIs (Drive, the
/// network/bridge, or the VPN service).
///
/// Construct it from the failing response (see [`ApiError::from_response`]);
/// it converts into [`anyhow::Error`] for free, so the existing
/// `anyhow::Result` call sites keep working:
///
/// ```no_run
/// # use internxt_core::ApiError;
/// # async fn demo(api: &internxt_core::api::DriveApi, token: &str, uuid: &str) -> anyhow::Result<()> {
/// if let Err(e) = api.get_folder_meta(token, uuid).await {
///     match e.downcast_ref::<ApiError>() {
///         // 404 -> tell the client the folder is gone, not "server error".
///         Some(api_err) if api_err.status_code() == 404 => { /* ... */ }
///         Some(api_err) => eprintln!("HTTP {}: {}", api_err.status_code(), api_err.detail().unwrap_or(api_err.body())),
///         None => eprintln!("{e:#}"),
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ApiError {
    context: String,
    status: StatusCode,
    body: String,
    detail: Option<String>,
}

impl ApiError {
    /// Build the error from an already-read body. `context` is the short call
    /// name used in the message (`"getFolderMeta"`, `"startUpload"`, ...); the
    /// detail message is extracted from `body` by [`ApiError::extract_detail`].
    pub fn new(context: impl Into<String>, status: StatusCode, body: impl Into<String>) -> Self {
        let body = body.into();
        let detail = Self::extract_detail(&body);
        ApiError {
            context: context.into(),
            status,
            body,
            detail,
        }
    }

    /// Consume a failed response and read its body into the error. Only call
    /// this once the status is known to be a failure — it drains the body.
    pub async fn from_response(context: impl Into<String>, resp: reqwest::Response) -> Self {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Self::new(context, status, body)
    }

    /// The upstream HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The upstream HTTP status as a plain number — handy for front-ends whose
    /// http types differ from reqwest's.
    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    /// The call that failed (`"getFolderMeta"`, `"startUpload"`, ...).
    pub fn context(&self) -> &str {
        &self.context
    }

    /// The raw response body, exactly as received (may be empty, may be
    /// non-JSON — e.g. an S3 XML error or a proxy's HTML page).
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The server-provided explanation, when the body carried one.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// Pull the human-readable detail out of a JSON error body, mirroring the
    /// Node CLI's `getErrorDetail`: Internxt's API answers with a `message`
    /// field that is either a string (`{"message":"Folder not found"}`) or an
    /// array of strings from the NestJS validation pipe
    /// (`{"message":["name must be a string","name should not be empty"]}`),
    /// which is joined with `", "`. Anything else — blank, missing, non-JSON —
    /// yields `None`.
    fn extract_detail(body: &str) -> Option<String> {
        let json: Value = serde_json::from_str(body).ok()?;
        match json.get("message")? {
            Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
            Value::Array(items) => {
                let parts: Vec<&str> = items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .collect();
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join(", "))
                }
            }
            _ => None,
        }
    }
}

/// Kept byte-for-byte compatible with the string this crate used to build, so
/// front-ends that only print the error show the same text as before. The body
/// is omitted when empty (it used to leave a dangling `": "`).
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: HTTP {}", self.context, self.status)?;
        if !self.body.is_empty() {
            write!(f, ": {}", self.body)?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_from_string_message() {
        let e = ApiError::new(
            "getFolderMeta",
            StatusCode::NOT_FOUND,
            r#"{"statusCode":404,"message":"Folder not found","error":"Not Found"}"#,
        );
        assert_eq!(e.detail(), Some("Folder not found"));
        assert_eq!(e.status_code(), 404);
        assert_eq!(e.status(), StatusCode::NOT_FOUND);
        assert_eq!(e.context(), "getFolderMeta");
    }

    #[test]
    fn detail_from_array_message_joins_with_comma() {
        let e = ApiError::new(
            "createFolder",
            StatusCode::BAD_REQUEST,
            r#"{"message":["name must be a string","name should not be empty"]}"#,
        );
        assert_eq!(
            e.detail(),
            Some("name must be a string, name should not be empty")
        );
    }

    #[test]
    fn no_detail_without_message_field() {
        let e = ApiError::new(
            "listFolders",
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"statusCode":500,"error":"Internal Server Error"}"#,
        );
        assert_eq!(e.detail(), None);
        assert_eq!(e.body(), r#"{"statusCode":500,"error":"Internal Server Error"}"#);
    }

    #[test]
    fn no_detail_from_blank_or_empty_message() {
        assert_eq!(
            ApiError::new("x", StatusCode::BAD_REQUEST, r#"{"message":"   "}"#).detail(),
            None
        );
        assert_eq!(
            ApiError::new("x", StatusCode::BAD_REQUEST, r#"{"message":[]}"#).detail(),
            None
        );
    }

    #[test]
    fn no_detail_from_non_json_body() {
        // S3 presigned URLs answer with XML, proxies with HTML.
        let e = ApiError::new(
            "downloadShard",
            StatusCode::FORBIDDEN,
            "<Error><Code>AccessDenied</Code></Error>",
        );
        assert_eq!(e.detail(), None);
        assert_eq!(e.status_code(), 403);
    }

    #[test]
    fn display_matches_the_legacy_message_and_skips_an_empty_body() {
        let e = ApiError::new("securityDetails", StatusCode::NOT_FOUND, "{\"a\":1}");
        assert_eq!(
            e.to_string(),
            "securityDetails failed: HTTP 404 Not Found: {\"a\":1}"
        );
        let empty = ApiError::new("downloadShard", StatusCode::NOT_FOUND, "");
        assert_eq!(empty.to_string(), "downloadShard failed: HTTP 404 Not Found");
    }

    #[test]
    fn status_survives_an_anyhow_round_trip() {
        fn failing() -> anyhow::Result<()> {
            Err(ApiError::new(
                "getFolderMeta",
                StatusCode::INSUFFICIENT_STORAGE,
                r#"{"message":"Not enough storage"}"#,
            )
            .into())
        }

        let err = failing().unwrap_err();
        // Printing is unchanged for callers that don't care about the status.
        assert!(err.to_string().starts_with("getFolderMeta failed: HTTP 507"));

        let api_err = err
            .downcast_ref::<ApiError>()
            .expect("ApiError survives the anyhow round-trip");
        assert_eq!(api_err.status_code(), 507);
        assert_eq!(api_err.detail(), Some("Not enough storage"));
    }
}
