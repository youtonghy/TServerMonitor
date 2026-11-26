//! Wire format between the daemon and the root ops helper (`tsmonitor helper`), protocol v2.
//!
//! One request per connection, newline-delimited JSON, at most [`MAX_LINE`] bytes:
//!
//! ```text
//! -> {"v":2,"auth":"<shared secret>","call":"nginx.write","args":{...},"dry_run":false,"actor":{...}}
//! <- {"type":"log","line":"..."}            (zero or more)
//! <- {"type":"result","data":{...}}         (exactly one terminal line, or)
//! <- {"type":"error","code":"...","message":"..."}
//! ```
//!
//! The envelope has no `op` key on purpose: the legacy package updater (`tsmonitor updater`)
//! requires one, so a v2 request sent to an old helper fails to parse instead of being run.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: u32 = 2;
pub const DEFAULT_SOCKET: &str = "/run/tsmonitor-helper/helper.sock";
/// Largest request line (file contents travel inside `args`).
pub const MAX_LINE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    /// web | mcp | system
    pub via: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Daemon-side job id, for correlating the helper's journal with the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u32,
    pub auth: String,
    pub call: String,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub actor: Actor,
}

/// Machine-readable error classes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Bad peer uid or secret.
    Unauthorized,
    /// The operation is not enabled in the helper config.
    NotAllowed,
    /// Arguments failed validation, or a safety guard refused the change.
    Invalid,
    /// Another change in the same domain is in progress or pending confirmation.
    Busy,
    /// The target changed since it was read (`base_sha256` mismatch).
    Conflict,
    /// The command ran and failed; the change was rolled back where possible.
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reply {
    Log { line: String },
    Result { data: Value },
    Error { code: ErrorCode, message: String },
}

/// Error carried from a helper handler to the wire.
#[derive(Debug)]
pub struct OpError {
    pub code: ErrorCode,
    pub message: String,
}

impl OpError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Invalid, message)
    }
    pub fn not_allowed(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotAllowed, message)
    }
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Failed, message)
    }
    pub fn busy(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Busy, message)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OpError {}

impl From<anyhow::Error> for OpError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<OpError>() {
            Ok(op) => op,
            Err(e) => OpError::failed(format!("{e:#}")),
        }
    }
}

pub type OpResult<T> = Result<T, OpError>;
