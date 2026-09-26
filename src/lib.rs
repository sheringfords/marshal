//! Sandboxed tool execution for agents.
//!
//! Three tools an agent commonly needs — filesystem, shell, and HTTP —
//! each behind a policy that denies by default.
//!
//! ```no_run
//! use std::sync::Arc;
//! use marshall::{FileSystemTool, Sandbox, ToolRegistry};
//!
//! # fn main() -> anyhow::Result<()> {
//! let sandbox = Sandbox::new(["/srv/agent/workspace"])?;
//!
//! let mut tools = ToolRegistry::new();
//! tools.register(Arc::new(FileSystemTool::new(sandbox)));
//! # Ok(())
//! # }
//! ```
//!
//! # What "sandboxed" means here, precisely
//!
//! It means each tool checks its target against an allowlist before acting:
//! paths must resolve inside a configured root, hosts must resolve to public
//! addresses, commands must be on a list. Every allowlist is empty by default,
//! so an unconfigured tool does nothing.
//!
//! It does **not** mean OS-level isolation. There is no seccomp filter, no
//! namespace, no chroot, and no separate process. A tool that gets past its
//! policy has the parent's full privileges. If you need real isolation, run
//! this inside something that provides it.
//!
//! The [`shell`] module in particular is a policy over *which binary runs*,
//! and a binary's arguments are usually enough to do anything that binary can
//! do. Read [`shell::ShellTool`] before enabling it.
//!
//! # Output is redacted by default
//!
//! Tools return a digest and a byte count rather than content. An agent
//! reading a file should not, as a side effect, copy that file into a
//! transcript, a log line, and an evidence record. Use
//! [`ToolOutcome::content`] when you actually need the bytes.

#![warn(missing_docs)]

pub mod agent;
pub mod backend;
pub mod code;
pub mod destination;
pub mod egress;
pub mod error;
/// The validation harness used to produce `validation/`.
///
/// Behind the `experiment` feature: it is a research artifact, and shipping it
/// in the default API means committing to its shape at 1.0. Nothing in the
/// library depends on it.
#[cfg(feature = "experiment")]
pub mod experiment;
pub mod fs;
pub mod http;
pub mod limits;
pub mod policy;
pub mod ratelimit;
pub mod redaction;
pub mod registry;
pub mod sandbox;
pub mod server;
pub mod shell;
pub mod system;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use agent::{MemoryTool, PlanTool, ReflectTool, ThinkTool, TodoTool};
pub use backend::{
    ContainerBackend, ExecOutput, ExecRequest, ExecutionBackend, LocalProcessBackend,
    ResourceLimits, StreamingOutput, WasmBackend,
};
pub use code::{CodeTool, Language};
pub use destination::{
    validate_destination, DestinationClass, DestinationError, ValidatedDestination,
};
pub use egress::{EgressError, EgressPolicy};
pub use error::ToolError;
pub use fs::FileSystemTool;
pub use http::HttpTool;
pub use limits::Limits;
pub use policy::ExecutionPolicy;
pub use ratelimit::{RateLimit, RateLimiter};
pub use redaction::REDACTION_POLICY_VERSION;
pub use registry::{ToolDefinition, ToolRegistry};
pub use sandbox::{Sandbox, SandboxError};
pub use server::ServerConfig;
pub use shell::{ArgumentPolicy, ShellTool};
pub use system::{SystemPolicy, SystemTool};

/// SHA-256 of `bytes` as lowercase hex.
///
/// Used to put a verifiable fingerprint of a payload into evidence without
/// putting the payload there.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// What a tool call produced.
///
/// A tool that ran and failed is an `Outcome` with `success: false`, not an
/// `Err`. `Err` is for a call that could not be attempted — an unknown tool, a
/// policy rejection, a malformed argument. The distinction matters to an agent
/// loop: the first is a result to reason about, the second is a bug.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutcome {
    /// Which tool ran.
    pub tool: String,
    /// Whether the tool considered its work successful.
    pub success: bool,
    /// Redacted, structured summary safe to log and store.
    pub summary: serde_json::Value,
    /// The actual payload, present only when the caller asked for it.
    ///
    /// Kept out of [`ToolOutcome::summary`] on purpose, so the cheap thing to
    /// do — log the outcome — is also the safe thing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<u8>>,
    /// Stable error code on failure. Never contains a path, host, or payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// How long the call took, in milliseconds.
    pub duration_ms: u64,
    /// Extra structured facts about the call.
    pub metadata: HashMap<String, String>,
}

impl ToolOutcome {
    /// A successful outcome.
    pub fn success(tool: impl Into<String>, summary: serde_json::Value, duration_ms: u64) -> Self {
        ToolOutcome {
            tool: tool.into(),
            success: true,
            summary,
            content: None,
            error_code: None,
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    /// A failed outcome, identified by a stable code.
    ///
    /// The code is deliberately not a message: error text is where paths,
    /// hostnames, and occasionally credentials leak into logs.
    pub fn failure(
        tool: impl Into<String>,
        error_code: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        let code = error_code.into();
        ToolOutcome {
            tool: tool.into(),
            success: false,
            summary: serde_json::json!({ "error_code": code }),
            content: None,
            error_code: Some(code),
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    /// Attach the raw payload.
    pub fn with_content(mut self, content: Vec<u8>) -> Self {
        self.content = Some(content);
        self
    }

    /// Attach one metadata entry.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A tool an agent can call.
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    /// Stable name used to invoke this tool.
    fn name(&self) -> &str;

    /// One-line description, shown to a planner.
    fn description(&self) -> &str;

    /// JSON Schema for the arguments.
    fn parameters_schema(&self) -> serde_json::Value;

    /// Check arguments against policy without doing anything.
    ///
    /// Called by [`ToolRegistry`] before every execution, and separately
    /// callable so a planner can test a call before committing to it.
    async fn validate(&self, args: &serde_json::Value) -> anyhow::Result<()> {
        let _ = args;
        Ok(())
    }

    /// Run the tool. Implementations must call [`Tool::validate`] themselves,
    /// since a tool may be invoked directly rather than through the registry.
    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolOutcome>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_failure_carries_a_code_and_no_prose() {
        let outcome = ToolOutcome::failure("fs", "not_found", 3);
        assert!(!outcome.success);
        assert_eq!(outcome.error_code.as_deref(), Some("not_found"));
        assert!(outcome.content.is_none());
    }

    #[test]
    fn content_is_absent_unless_requested() {
        let outcome = ToolOutcome::success("fs", serde_json::json!({}), 1);
        assert!(outcome.content.is_none());

        let with = outcome.clone().with_content(b"payload".to_vec());
        assert_eq!(with.content.as_deref(), Some(&b"payload"[..]));
    }

    #[test]
    fn serialized_outcomes_omit_absent_content() {
        // The default log line must not carry a `"content": null` that invites
        // someone to start populating it.
        let outcome = ToolOutcome::success("fs", serde_json::json!({"ok": true}), 1);
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(!json.contains("content"), "{json}");
    }
}
