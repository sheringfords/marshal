//! One authoritative execution identity.
//!
//! Caller arguments describe *requested* work; trusted authority is runtime
//! state that must never be encoded inside those arguments. [`ExecutionContract`]
//! is created once per admitted execution by the coordinator and travels
//! coordinator → registry → tool boundary unchanged:
//!
//! - [`ExecutionScope`] is the typed trusted scope (a session root, or an
//!   explicit workspace-wide trusted-local grant). Tools enforce it; no tool
//!   reads scope out of caller JSON.
//! - `request_fingerprint` binds tool identity, canonical caller arguments
//!   and trusted scope into one replay identity, so an idempotency key can
//!   never silently represent two different executions.
//! - `policy_identity` names the policy snapshot that admitted the work, so
//!   audit records say *under what rules* an execution ran.
//!
//! The contract is immutable after admission. It carries no permits, handles
//! or mutable runtime state.

use std::path::PathBuf;

/// Trusted execution scope, derived from the admitted session or workspace.
///
/// There is no "no scope" state: [`ExecutionScope::Workspace`] is the
/// explicit trusted-local grant used for session-less requests and direct
/// library calls. Absence-by-accident is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionScope {
    /// Confined to this canonical session root.
    Session(PathBuf),
    /// Trusted-local: the tool's own policy bounds apply.
    Workspace,
}

impl ExecutionScope {
    /// Stable, non-secret representation bound into the request fingerprint.
    /// Session roots are unique per session, so distinct sessions always
    /// fingerprint distinctly even for identical tool + arguments.
    fn repr(&self) -> String {
        match self {
            ExecutionScope::Session(root) => format!("session:{}", root.display()),
            ExecutionScope::Workspace => "workspace".to_string(),
        }
    }
}

/// One admitted execution: fresh id, trusted scope, replay identity, policy.
///
/// Constructed only by [`ExecutionContract::admit`] / [`ExecutionContract::local`],
/// which always derive the fingerprint from exactly the tool, arguments and
/// scope they are given — so a contract can never disagree with the call it
/// was built for. Fields are private: callers read through accessors and
/// cannot mutate the identity after admission. The registry executes the
/// [`ContractedCall`](crate::ContractedCall) unit (tool + args + contract)
/// rather than accepting the three independently, which is what makes a
/// contract/call mismatch unrepresentable at the execution boundary.
#[derive(Debug, Clone)]
pub struct ExecutionContract {
    /// Fresh server-generated opaque identity for one admitted execution.
    /// Shared by dispatch, replay matching and audit — never duplicated into
    /// parallel request/audit/replay id systems.
    execution_id: String,
    /// Typed trusted authority for this execution.
    scope: ExecutionScope,
    /// Canonical digest over operation identity, canonical arguments and
    /// trusted scope. Deterministic for identical work, distinct for any
    /// change of tool, arguments or scope. A one-way hash: safe to record.
    request_fingerprint: String,
    /// Identity of the policy snapshot that admitted the work (content hash
    /// of the effective policy, or the ad-hoc marker for hand-built
    /// registries). Recorded in audit, never trusted from the caller.
    policy_identity: String,
}

impl ExecutionContract {
    /// Admit one execution: mint a fresh id and bind the replay identity.
    /// The fingerprint intentionally excludes `execution_id` — retries of the
    /// same work must match; distinct work must not.
    pub fn admit(
        scope: ExecutionScope,
        tool: &str,
        args: &serde_json::Value,
        policy_identity: String,
    ) -> Self {
        ExecutionContract {
            execution_id: uuid::Uuid::new_v4().to_string(),
            request_fingerprint: Self::fingerprint(tool, &scope, args),
            scope,
            policy_identity,
        }
    }

    /// Explicit trusted-local contract for direct library use without HTTP
    /// admission. The Workspace scope is stated, not defaulted.
    pub fn local(tool: &str, args: &serde_json::Value, policy_identity: &str) -> Self {
        Self::admit(
            ExecutionScope::Workspace,
            tool,
            args,
            policy_identity.to_string(),
        )
    }

    /// Canonical digest binding operation identity to tool, canonical
    /// arguments and trusted scope. Canonical JSON sorts every object key
    /// recursively, so JSON object insertion order cannot change the digest.
    /// Internal: only [`ExecutionContract::admit`] mints fingerprints, which
    /// keeps every fingerprint consistent with its contract's tool, arguments
    /// and scope by construction.
    fn fingerprint(tool: &str, scope: &ExecutionScope, args: &serde_json::Value) -> String {
        let input = serde_json::json!({
            "v": 1,
            "tool": tool,
            "scope": scope.repr(),
            "args": args,
        });
        crate::sha256_hex(canonical_json(&input).as_bytes())
    }

    /// Session root when this execution runs under a session.
    pub fn session_root(&self) -> Option<&PathBuf> {
        match &self.scope {
            ExecutionScope::Session(root) => Some(root),
            ExecutionScope::Workspace => None,
        }
    }

    /// The admitted execution's opaque identity.
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    /// The admitted trusted scope.
    pub fn scope(&self) -> &ExecutionScope {
        &self.scope
    }

    /// The replay fingerprint bound at admission.
    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    /// The admitting policy snapshot's identity.
    pub fn policy_identity(&self) -> &str {
        &self.policy_identity
    }
}

/// Marker recorded when a registry is hand-built without a policy file
/// (crate::ToolRegistry::new). Server-built registries carry the content hash of
/// the effective policy instead.
pub const ADHOC_POLICY_IDENTITY: &str = "marshall-adhoc-registry-v1";

/// Deterministic JSON encoding: object keys sorted byte-wise at every level.
/// Scalar rendering matches `serde_json`, so equal values always encode
/// equally regardless of how the `Value` was constructed.
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => value.to_string(),
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                out.push_str(&canonical_json(&map[*k]));
            }
            out.push('}');
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fingerprint_ignores_object_insertion_order() {
        let a = json!({"x": 1, "y": {"b": 2, "a": 1}, "z": [3, {"q": 1, "p": 0}]});
        let b = json!({"z": [3, {"p": 0, "q": 1}], "y": {"a": 1, "b": 2}, "x": 1});
        let scope = ExecutionScope::Workspace;
        assert_eq!(
            ExecutionContract::fingerprint("t", &scope, &a),
            ExecutionContract::fingerprint("t", &scope, &b)
        );
    }

    #[test]
    fn fingerprint_separates_tool_args_and_scope() {
        let args = json!({"v": 1});
        let ws = ExecutionScope::Workspace;
        let sess = ExecutionScope::Session(PathBuf::from("/tmp/s1"));
        let base = ExecutionContract::fingerprint("t", &ws, &args);
        assert_ne!(base, ExecutionContract::fingerprint("other", &ws, &args));
        assert_ne!(
            base,
            ExecutionContract::fingerprint("t", &ws, &json!({"v": 2}))
        );
        assert_ne!(base, ExecutionContract::fingerprint("t", &sess, &args));
        assert_ne!(
            base,
            ExecutionContract::fingerprint(
                "t",
                &ExecutionScope::Session(PathBuf::from("/tmp/s2")),
                &args
            )
        );
    }

    #[test]
    fn fingerprint_contains_no_caller_material() {
        // The digest is a fixed-size hex string: safe to record even when
        // the arguments carry secrets.
        let fp = ExecutionContract::fingerprint(
            "t",
            &ExecutionScope::Workspace,
            &json!({"password": "hunter2"}),
        );
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!fp.contains("hunter2"));
    }

    #[test]
    fn fresh_admissions_mint_distinct_execution_ids_for_identical_work() {
        let a =
            ExecutionContract::admit(ExecutionScope::Workspace, "t", &json!({}), "p".to_string());
        let b =
            ExecutionContract::admit(ExecutionScope::Workspace, "t", &json!({}), "p".to_string());
        assert_ne!(a.execution_id(), b.execution_id());
        // ...while the replay identity matches, so retries join.
        assert_eq!(a.request_fingerprint(), b.request_fingerprint());
    }
}
