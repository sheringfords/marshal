//! Reading, writing, and listing inside a sandbox.

use std::time::Instant;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};
use tokio::fs;
#[allow(unused_imports)]
use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::sandbox::{Sandbox, SandboxError};
use crate::{sha256_hex, Tool, ToolOutcome};

/// Default cap on a single read.
pub const DEFAULT_READ_LIMIT: usize = 8 * 1024 * 1024;

/// Filesystem access restricted to a [`Sandbox`].
///
/// Every path is canonicalized and checked against the sandbox roots before
/// any I/O happens, which is what stops a symlink or a sibling directory with
/// a shared name prefix from reaching outside. See [`crate::sandbox`] for the
/// two escapes this replaced and the race it still does not close.
///
/// Reads return a digest and a byte count in the summary; the bytes themselves
/// go in [`ToolOutcome::content`], so logging an outcome does not copy the file
/// into your logs.
pub struct FileSystemTool {
    sandbox: Sandbox,
    read_limit: usize,
    writable: bool,
}

impl FileSystemTool {
    /// A read-only filesystem tool over `sandbox`.
    ///
    /// Read-only by default: granting write access is a decision that should
    /// be visible at the call site.
    pub fn new(sandbox: Sandbox) -> Self {
        FileSystemTool {
            sandbox,
            read_limit: DEFAULT_READ_LIMIT,
            writable: false,
        }
    }

    /// Permit `write` operations.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// Cap how many bytes a single read may return.
    pub fn with_read_limit(mut self, bytes: usize) -> Self {
        // Clamp to prevent 0 (returns empty) or absurdly large (OOM)
        let clamped = bytes.clamp(1, 64 * 1024 * 1024);
        self.read_limit = clamped;
        self
    }

    fn operation(args: &Value) -> Result<&str> {
        args.get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'operation'"))
    }

    fn raw_path(args: &Value) -> Result<&str> {
        args.get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'path'"))
    }

    /// Trusted session root bound by the server after admission, if any.
    ///
    /// The server strips caller-supplied values before admission and injects
    /// the canonical root from its own session table, so a present value is
    /// authoritative. Only absolute paths qualify; anything else is treated
    /// as no scope (fail open would be wrong here only if the server lied,
    /// and the server never sends a relative root).
    fn scope_root(args: &Value) -> Option<std::path::PathBuf> {
        let s = args.get(crate::server::SESSION_SCOPE_KEY)?.as_str()?;
        let p = std::path::PathBuf::from(s);
        p.is_absolute().then_some(p)
    }

    /// Resolve an existing path through the workspace sandbox and require it
    /// inside the session scope when one is bound. Returned paths are
    /// canonical, so the prefix check is component-wise.
    fn resolve_scoped_existing(&self, args: &Value, raw: &str) -> Result<std::path::PathBuf> {
        let resolved = self.sandbox.resolve_existing(raw).map_err(policy_error)?;
        self.check_scope(args, &resolved)?;
        Ok(resolved)
    }

    /// Resolve a creatable path through the workspace sandbox and require it
    /// inside the session scope when one is bound.
    fn resolve_scoped_for_create(&self, args: &Value, raw: &str) -> Result<std::path::PathBuf> {
        let resolved = self.sandbox.resolve_for_create(raw).map_err(policy_error)?;
        self.check_scope(args, &resolved)?;
        Ok(resolved)
    }

    /// Roots that contained paths must stay inside: the session root when the
    /// call runs under a session, otherwise the tool's sandbox roots.
    fn effective_roots(&self, args: &Value) -> Vec<std::path::PathBuf> {
        if let Some(scope) = Self::scope_root(args) {
            vec![scope]
        } else {
            self.sandbox.roots().to_vec()
        }
    }

    /// Require an already-resolved (canonical) path to stay inside the
    /// effective roots. Sandbox resolution guarantees canonical form, so a
    /// component-wise prefix check is sound here (remaining TOCTOU between
    /// check and I/O is M2-003 territory and documented as such).
    fn check_scope(&self, args: &Value, resolved: &std::path::Path) -> Result<()> {
        if Self::scope_root(args).is_some()
            && !Self::inside_roots(&self.effective_roots(args), resolved)
        {
            anyhow::bail!("path_not_allowed");
        }
        Ok(())
    }

    fn inside_roots(roots: &[std::path::PathBuf], canonical: &std::path::Path) -> bool {
        roots.iter().any(|r| canonical.starts_with(r))
    }

    /// Scope check for paths that do not resolve (the `exists` probe).
    ///
    /// Walks up to the longest existing prefix, canonicalizes it, and
    /// requires it inside the session root. A probe whose nearest existing
    /// ancestor already escapes the session is denied rather than reported
    /// absent, so `exists` cannot oracle session-external layout.
    fn scope_probe(&self, args: &Value, raw: &str) -> Result<()> {
        let Some(scope) = Self::scope_root(args) else {
            return Ok(());
        };
        let mut candidate = std::path::PathBuf::from(raw);
        loop {
            match candidate.canonicalize() {
                Ok(canonical) => {
                    if !canonical.starts_with(&scope) {
                        anyhow::bail!("path_not_allowed");
                    }
                    return Ok(());
                }
                Err(_) => {
                    if !candidate.pop() {
                        anyhow::bail!("path_not_allowed");
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Tool for FileSystemTool {
    fn name(&self) -> &str {
        "filesystem"
    }

    fn description(&self) -> &str {
        "Filesystem within sandbox — read/write/list/mkdir/delete/stat/copy/move/append/search/glob/patch/exists. Use read to inspect, search/glob to discover, write/patch to edit. Prefer patch for single-line edits, write for new files. All paths must be inside sandbox; see sandbox error codes."
    }

    fn parameters_schema(&self) -> Value {
        let operations: Vec<&str> = if self.writable {
            vec![
                "read", "write", "list", "mkdir", "delete", "stat", "copy", "move", "append",
                "search", "glob", "patch", "exists",
            ]
        } else {
            vec!["read", "list", "stat", "search", "glob", "exists"]
        };
        json!({
            "type": "object",
            "properties": {
                "operation": { "type": "string", "enum": operations, "description": "Filesystem operation. read: get file content (capped 8MiB). write: create/overwrite. patch: single replace. search: substring grep (1000 cap). glob: pattern match. Examples: read /tmp/work/a.txt, search /tmp/work for 'todo' recursive true" },
                "path": { "type": "string", "description": "Absolute path inside sandbox (or base dir for glob/search). Example: /tmp/marshalld/<session>/file.txt" },
                "content": { "type": "string", "description": "UTF-8 bytes to write (write/append only). Example: write with content 'hello world'" },
                "content_base64": { "type": "string", "description": "Base64 bytes for binary writes (alternative to content). Example: write PNG via content_base64" },
                "destination": { "type": "string", "description": "Destination path for copy/move. Must be inside sandbox." },
                "pattern": { "type": "string", "description": "Pattern for search (substring) or glob (e.g. **/*.py, *.txt). Keep <1024 chars, no .. or leading /." },
                "recursive": { "type": "boolean", "description": "Search recursively (default false). Use true to walk subdirs.", "default": false },
                "search": { "type": "string", "description": "Search string for patch (must exist, non-empty). Example: old text to replace." },
                "replace": { "type": "string", "description": "Replacement for patch. Single occurrence only." }
            },
            "required": ["operation", "path"],
            "examples": [
                {"operation":"read","path":"/tmp/marshalld/abc/file.txt"},
                {"operation":"search","path":"/tmp/marshalld/abc","pattern":"todo","recursive":true},
                {"operation":"patch","path":"/tmp/marshalld/abc/main.py","search":"old","replace":"new"}
            ]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        let operation = Self::operation(args)?;
        let path = Self::raw_path(args)?;

        match operation {
            "exists" => {
                // Read-only probe: missing -> exists:false, outside -> policy error
                // (so it cannot be used as an oracle for paths outside the sandbox).
                // A session scope narrows "outside" to outside the session root.
                match self.sandbox.resolve_existing(path) {
                    Ok(p) => {
                        self.check_scope(args, &p)?;
                        Ok(())
                    }
                    Err(SandboxError::Unresolvable) => {
                        // Missing paths reveal nothing, but a scope still
                        // confines the probe: an unresolvable path whose
                        // longest existing prefix escapes the session is
                        // denied rather than reported absent.
                        self.scope_probe(args, path)?;
                        Ok(())
                    }
                    Err(e) => Err(policy_error(e)),
                }?;
            }
            "read" | "list" | "stat" | "search" | "glob" => {
                let _ = self.resolve_scoped_existing(args, path)?;
                if operation == "search" {
                    let pat = args
                        .get("pattern")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("missing 'pattern' for search"))?;
                    if pat.len() > 1024 {
                        anyhow::bail!("pattern_too_long");
                    }
                }
                if operation == "glob" {
                    let pat = args
                        .get("pattern")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("missing 'pattern' for glob"))?;
                    if pat.len() > 1024 {
                        anyhow::bail!("pattern_too_long");
                    }
                    if pat.contains("..") || pat.starts_with('/') {
                        anyhow::bail!("invalid glob pattern");
                    }
                }
            }
            "write" | "append" => {
                if !self.writable {
                    anyhow::bail!("writes_not_permitted");
                }
                let _ = self.resolve_scoped_for_create(args, path)?;
                let has_str = args.get("content").and_then(Value::as_str).is_some();
                let has_b64 = args.get("content_base64").and_then(Value::as_str).is_some();
                if !has_str && !has_b64 {
                    anyhow::bail!("missing 'content' or 'content_base64' for write");
                }
                if has_str && has_b64 {
                    anyhow::bail!("provide only one of 'content' or 'content_base64'");
                }
                if has_b64 {
                    BASE64
                        .decode(args.get("content_base64").unwrap().as_str().unwrap())
                        .map_err(|_| anyhow::anyhow!("invalid_base64"))?;
                }
            }
            "mkdir" | "delete" => {
                if !self.writable {
                    anyhow::bail!("writes_not_permitted");
                }
                if operation == "delete" {
                    let _ = self.resolve_scoped_existing(args, path)?;
                } else {
                    let _ = self.resolve_scoped_for_create(args, path)?;
                }
            }
            "copy" | "move" => {
                if !self.writable {
                    anyhow::bail!("writes_not_permitted");
                }
                let _ = self.resolve_scoped_existing(args, path)?;
                let dest = args
                    .get("destination")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'destination' for copy/move"))?;
                let _ = self.resolve_scoped_for_create(args, dest)?;
            }
            "patch" => {
                if !self.writable {
                    anyhow::bail!("writes_not_permitted");
                }
                let _ = self.resolve_scoped_existing(args, path)?;
                let search = args
                    .get("search")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'search' for patch"))?;
                if search.is_empty() {
                    anyhow::bail!("search_empty");
                }
                if search.len() > 4096 {
                    anyhow::bail!("search_too_long");
                }
                let replace = args
                    .get("replace")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'replace' for patch"))?;
                if replace.len() > 4096 {
                    anyhow::bail!("replace_too_long");
                }
            }
            other => anyhow::bail!("unsupported_operation: {other}"),
        }
        Ok(())
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;

        let operation = Self::operation(&args)?;
        let raw = Self::raw_path(&args)?;
        debug!(operation, "filesystem");

        match operation {
            "read" => {
                // Scope is checked on the canonical path even on Linux, where
                // I/O itself goes through an fd opened workspace-wide.
                let _ = Self::scope_root(&args)
                    .map(|_| self.resolve_scoped_existing(&args, raw))
                    .transpose()?;
                // Linux: use openat2 fd for I/O to close TOCTOU (darwin falls back to check-then-open)
                #[cfg(target_os = "linux")]
                let read_result = {
                    match self.sandbox.open_existing_file(raw) {
                        Ok(std_file) => {
                            let tokio_file = tokio::fs::File::from_std(std_file);
                            read_capped_from_file(tokio_file, self.read_limit).await
                        }
                        Err(e) => Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            e.to_string(),
                        )),
                    }
                };
                #[cfg(not(target_os = "linux"))]
                let read_result = {
                    let path = self.resolve_scoped_existing(&args, raw)?;
                    read_file_capped(&path, self.read_limit).await
                };
                #[cfg(target_os = "linux")]
                let read_outcome = match read_result {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok((bytes, total, truncated)) => {
                        let digest = sha256_hex(&bytes);
                        Ok(ToolOutcome::success(
                            "filesystem",
                            json!({
                                "operation": "read",
                                "bytes": bytes.len(),
                                "file_bytes": total,
                                "truncated": truncated,
                                "sha256": digest,
                                "content_redacted": true,
                                "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                            }),
                            elapsed(started),
                        )
                        .with_content(bytes)
                        .with_metadata("operation", "read"))
                    }
                };
                #[cfg(not(target_os = "linux"))]
                let read_outcome = match read_result {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok((bytes, total, truncated)) => {
                        let digest = sha256_hex(&bytes);
                        Ok(ToolOutcome::success(
                            "filesystem",
                            json!({
                                "operation": "read",
                                "bytes": bytes.len(),
                                "file_bytes": total,
                                "truncated": truncated,
                                "sha256": digest,
                                "content_redacted": true,
                                "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                            }),
                            elapsed(started),
                        )
                        .with_content(bytes)
                        .with_metadata("operation", "read"))
                    }
                };
                read_outcome
            }

            "write" => {
                let path = self.resolve_scoped_for_create(&args, raw)?;
                let bytes: Vec<u8> = if let Some(s) = args.get("content").and_then(Value::as_str) {
                    s.as_bytes().to_vec()
                } else if let Some(b64) = args.get("content_base64").and_then(Value::as_str) {
                    BASE64
                        .decode(b64)
                        .map_err(|_| anyhow::anyhow!("invalid_base64"))?
                } else {
                    anyhow::bail!("missing 'content'");
                };

                match fs::write(&path, &bytes).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({
                            "operation": "write",
                            "bytes": bytes.len(),
                            "sha256": sha256_hex(&bytes),
                            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                        }),
                        elapsed(started),
                    )
                    .with_metadata("operation", "write")),
                }
            }

            "mkdir" => {
                let path = self.resolve_scoped_for_create(&args, raw)?;
                match fs::create_dir_all(&path).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "mkdir", "path": path.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "mkdir")),
                }
            }

            "stat" => {
                let path = self.resolve_scoped_existing(&args, raw)?;
                match fs::metadata(&path).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(m) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({
                            "operation": "stat",
                            "path": path.display().to_string(),
                            "is_file": m.is_file(),
                            "is_dir": m.is_dir(),
                            "len": m.len(),
                            "readonly": m.permissions().readonly(),
                        }),
                        elapsed(started),
                    )
                    .with_metadata("operation", "stat")),
                }
            }

            "copy" => {
                let src = self.resolve_scoped_existing(&args, raw)?;
                let dest_raw = args
                    .get("destination")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'destination'"))?;
                let dest = self.resolve_scoped_for_create(&args, dest_raw)?;
                // ensure src and dest are not same
                if src == dest {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "same_file",
                        elapsed(started),
                    ));
                }
                match fs::copy(&src, &dest).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(n) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "copy", "bytes": n, "src": src.display().to_string(), "dest": dest.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "copy")),
                }
            }

            "move" => {
                let src = self.resolve_scoped_existing(&args, raw)?;
                let dest_raw = args
                    .get("destination")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'destination'"))?;
                let dest = self.resolve_scoped_for_create(&args, dest_raw)?;
                if self.sandbox.roots().iter().any(|r| r == &src)
                    || Self::scope_root(&args).as_deref() == Some(src.as_path())
                {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "refused_move_root",
                        elapsed(started),
                    ));
                }
                match fs::rename(&src, &dest).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "move", "src": src.display().to_string(), "dest": dest.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "move")),
                }
            }

            "append" => {
                let path = self.resolve_scoped_for_create(&args, raw)?;
                let bytes: Vec<u8> = if let Some(s) = args.get("content").and_then(Value::as_str) {
                    s.as_bytes().to_vec()
                } else if let Some(b64) = args.get("content_base64").and_then(Value::as_str) {
                    BASE64
                        .decode(b64)
                        .map_err(|_| anyhow::anyhow!("invalid_base64"))?
                } else {
                    anyhow::bail!("missing 'content'");
                };
                // Append via read + write to avoid needing OpenOptions; keeps sandbox check simple
                let existing = fs::read(&path).await.unwrap_or_default();
                let mut combined = existing;
                combined.extend_from_slice(&bytes);
                match fs::write(&path, &combined).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "append", "bytes": bytes.len(), "sha256": sha256_hex(&bytes)}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "append")),
                }
            }

            "search" => {
                let path = self.resolve_scoped_existing(&args, raw)?;
                let pattern = args.get("pattern").and_then(Value::as_str).unwrap_or("");
                let recursive = args
                    .get("recursive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let mut matches = Vec::new();
                let mut count = 0usize;
                // Simple substring search, not regex, to avoid ReDoS.
                let search_path = path.clone();
                let pat = pattern.to_string();
                // For single file, just grep it with size cap.
                let meta = fs::metadata(&search_path).await;
                if let Ok(m) = meta {
                    if m.is_file() {
                        if m.len() > self.read_limit as u64 * 4 {
                            // Skip huge files to avoid OOM
                        } else if let Ok((bytes, _, _)) =
                            read_file_capped(&search_path, self.read_limit.min(1024 * 1024)).await
                        {
                            let content = String::from_utf8_lossy(&bytes);
                            for (idx, line) in content.lines().enumerate() {
                                if line.contains(&pat) {
                                    matches.push(json!({"file": search_path.display().to_string(), "line": idx + 1, "text": line.chars().take(512).collect::<String>()}));
                                    count += 1;
                                    if count >= 1000 {
                                        break;
                                    }
                                }
                            }
                        }
                    } else if m.is_dir() {
                        // Walk dir one level or recursive
                        let mut stack = vec![search_path];
                        while let Some(dir) = stack.pop() {
                            if let Ok(mut entries) = fs::read_dir(&dir).await {
                                while let Ok(Some(entry)) = entries.next_entry().await {
                                    if let Ok(ft) = entry.file_type().await {
                                        let p = entry.path();
                                        if ft.is_dir() && recursive {
                                            // ensure stays inside the effective roots
                                            if let Ok(canonical) = p.canonicalize() {
                                                if Self::inside_roots(
                                                    &self.effective_roots(&args),
                                                    &canonical,
                                                ) {
                                                    stack.push(p);
                                                }
                                            }
                                        } else if ft.is_file() {
                                            // Ensure file itself is inside the effective roots (symlink check).
                                            if let Ok(canonical) = p.canonicalize() {
                                                if !Self::inside_roots(
                                                    &self.effective_roots(&args),
                                                    &canonical,
                                                ) {
                                                    continue;
                                                }
                                            } else {
                                                continue;
                                            }
                                            // Cap per-file read to avoid OOM on large files
                                            if let Ok(meta) = tokio::fs::metadata(&p).await {
                                                if meta.len() <= self.read_limit as u64 * 4 {
                                                    if let Ok((bytes, _, _)) = read_file_capped(
                                                        &p,
                                                        self.read_limit.min(1024 * 1024),
                                                    )
                                                    .await
                                                    {
                                                        let content =
                                                            String::from_utf8_lossy(&bytes);
                                                        for (idx, line) in
                                                            content.lines().enumerate()
                                                        {
                                                            if line.contains(&pat) {
                                                                matches.push(json!({"file": p.display().to_string(), "line": idx + 1, "text": line.chars().take(512).collect::<String>()}));
                                                                count += 1;
                                                                if count >= 1000 {
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            if count >= 1000 {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if count >= 1000 {
                                break;
                            }
                        }
                    }
                }
                Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "search", "pattern": pat, "matches": matches, "count": count}),
                    elapsed(started),
                )
                .with_metadata("operation", "search"))
            }

            "glob" => {
                let base = self.resolve_scoped_existing(&args, raw)?;
                let pattern = args.get("pattern").and_then(Value::as_str).unwrap_or("*");
                // Build glob pattern relative to base, e.g. base + "/" + pattern
                let full_pattern = format!("{}/{}", base.display(), pattern);
                let mut matches = Vec::new();
                if let Ok(paths) = glob::glob(&full_pattern) {
                    for entry in paths.flatten() {
                        // Must canonicalize and be inside the effective roots; deny if canonical fails.
                        if let Ok(canonical) = entry.canonicalize() {
                            if Self::inside_roots(&self.effective_roots(&args), &canonical) {
                                matches.push(entry.display().to_string());
                            }
                        }
                        if matches.len() >= 1000 {
                            break;
                        }
                    }
                }
                matches.sort();
                Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "glob", "pattern": pattern, "matches": matches, "count": matches.len()}),
                    elapsed(started),
                )
                .with_metadata("operation", "glob"))
            }

            "patch" => {
                let path = self.resolve_scoped_existing(&args, raw)?;
                let search = args.get("search").and_then(Value::as_str).unwrap_or("");
                let replace = args.get("replace").and_then(Value::as_str).unwrap_or("");
                if search.is_empty() {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "search_empty",
                        elapsed(started),
                    ));
                }
                // Cap file size for patch
                let meta = fs::metadata(&path)
                    .await
                    .map_err(|e| anyhow::anyhow!("{}", io_code(&e)))?;
                if meta.len() > self.read_limit as u64 {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "file_too_large",
                        elapsed(started),
                    ));
                }
                let content = fs::read_to_string(&path)
                    .await
                    .map_err(|e| anyhow::anyhow!("{}", io_code(&e)))?;
                if !content.contains(search) {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "search_not_found",
                        elapsed(started),
                    ));
                }
                let new_content = content.replacen(search, replace, 1);
                let changed = new_content != content;
                if changed {
                    fs::write(&path, new_content.as_bytes())
                        .await
                        .map_err(|e| anyhow::anyhow!("{}", io_code(&e)))?;
                }
                Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "patch", "changed": changed, "sha256": sha256_hex(new_content.as_bytes())}),
                    elapsed(started),
                )
                .with_metadata("operation", "patch"))
            }

            "delete" => {
                let path = self.resolve_scoped_existing(&args, raw)?;
                // refuse to delete the sandbox root — or the session root — itself
                if self.sandbox.roots().iter().any(|r| r == &path)
                    || Self::scope_root(&args).as_deref() == Some(path.as_path())
                {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "refused_delete_root",
                        elapsed(started),
                    ));
                }
                let meta = tokio::fs::symlink_metadata(&path).await;
                let result = match meta {
                    Ok(m) if m.is_dir() => fs::remove_dir_all(&path).await,
                    Ok(_) => fs::remove_file(&path).await,
                    Err(e) => Err(e),
                };
                match result {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "delete", "path": path.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "delete")),
                }
            }

            "list" => {
                let path = self.resolve_scoped_existing(&args, raw)?;
                if !path.is_dir() {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "not_a_directory",
                        elapsed(started),
                    ));
                }

                match fs::read_dir(&path).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(mut entries) => {
                        let mut names = Vec::new();
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            names.push(entry.file_name().to_string_lossy().into_owned());
                        }
                        names.sort();

                        // Names are returned: a listing is not useful without
                        // them, and a caller who asked to list a directory they
                        // are already permitted to read learns nothing new.
                        Ok(ToolOutcome::success(
                            "filesystem",
                            json!({
                                "operation": "list",
                                "entry_count": names.len(),
                                "entries": names,
                            }),
                            elapsed(started),
                        )
                        .with_metadata("operation", "list"))
                    }
                }
            }

            "exists" => match self.sandbox.resolve_existing(raw) {
                Ok(p) => {
                    self.check_scope(&args, &p)?;
                    Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "exists", "exists": true, "path": p.display().to_string()}),
                    elapsed(started),
                )
                .with_metadata("operation", "exists"))
                }
                Err(SandboxError::Unresolvable) => {
                    self.scope_probe(&args, raw)?;
                    Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "exists", "exists": false}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "exists"))
                }
                Err(e) => Err(policy_error(e)),
            },

            other => Ok(ToolOutcome::failure(
                "filesystem",
                format!("unsupported_operation:{other}"),
                elapsed(started),
            )),
        }
    }
}

/// Map a sandbox rejection to a stable code that reveals nothing about layout.
///
/// Distinguishing "outside the sandbox" from "does not exist" in a message
/// would let a caller map the filesystem by probing.
fn policy_error(err: SandboxError) -> anyhow::Error {
    match err {
        SandboxError::Outside | SandboxError::Unresolvable | SandboxError::NoRoots => {
            anyhow::anyhow!("path_not_allowed")
        }
        SandboxError::BadRoot { .. } => anyhow::anyhow!("sandbox_misconfigured"),
    }
}

fn io_code(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        std::io::ErrorKind::IsADirectory => "is_a_directory",
        _ => "io_error",
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

async fn read_file_capped(
    path: &std::path::Path,
    limit: usize,
) -> std::io::Result<(Vec<u8>, usize, bool)> {
    let mut file = tokio::fs::File::open(path).await?;
    read_capped_from_file_helper(&mut file, limit).await
}

#[cfg(target_os = "linux")]
async fn read_capped_from_file(
    mut file: tokio::fs::File,
    limit: usize,
) -> std::io::Result<(Vec<u8>, usize, bool)> {
    read_capped_from_file_helper(&mut file, limit).await
}

async fn read_capped_from_file_helper<R>(
    file: &mut R,
    limit: usize,
) -> std::io::Result<(Vec<u8>, usize, bool)>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    let mut buf = Vec::new();
    let mut total: usize = 0;
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = file.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n);
        if buf.len() < limit {
            let room = limit - buf.len();
            buf.extend_from_slice(&chunk[..n.min(room)]);
            if n > room {
                truncated = true;
            }
        } else {
            truncated = true;
        }
        // If file is huge, keep counting but not buffering beyond limit
        if total > limit && buf.len() >= limit {
            // Continue draining to get accurate file size but without extra allocation
            // We already counted; just drain remaining without storing
            // To avoid infinite loop on infinite file, cap counting at limit*2 for total accuracy?
            // We keep reading to get true total until EOF
        }
    }
    let was_truncated = truncated || total > limit;
    Ok((buf, total, was_truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fixture {
        base: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("exectool_fs_{name}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("safe")).unwrap();
            Fixture { base }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.base.join(rel)
        }

        fn tool(&self) -> FileSystemTool {
            FileSystemTool::new(Sandbox::new([self.base.join("safe")]).unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[tokio::test]
    async fn reads_a_file_inside_the_sandbox() {
        let f = Fixture::new("read");
        std::fs::write(f.path("safe/hello.txt"), "contents").unwrap();

        let outcome = f
            .tool()
            .execute(
                json!({"operation": "read", "path": f.path("safe/hello.txt").to_string_lossy()}),
            )
            .await
            .unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.content.as_deref(), Some(&b"contents"[..]));
        assert_eq!(outcome.summary["sha256"], json!(sha256_hex(b"contents")));
    }

    #[tokio::test]
    async fn the_sibling_prefix_escape_is_closed() {
        let f = Fixture::new("sibling");
        std::fs::create_dir_all(f.path("safe_evil")).unwrap();
        std::fs::write(f.path("safe_evil/stolen.txt"), "secret").unwrap();

        let err = f
            .tool()
            .execute(json!({"operation": "read", "path": f.path("safe_evil/stolen.txt").to_string_lossy()}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn the_symlink_escape_is_closed() {
        let f = Fixture::new("symlink");
        std::fs::create_dir_all(f.path("outside")).unwrap();
        std::fs::write(f.path("outside/secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(f.path("outside"), f.path("safe/link")).unwrap();

        let err = f
            .tool()
            .execute(json!({"operation": "read", "path": f.path("safe/link/secret.txt").to_string_lossy()}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
    }

    #[tokio::test]
    async fn writes_are_denied_unless_enabled() {
        let f = Fixture::new("readonly");
        let err = f
            .tool()
            .execute(json!({
                "operation": "write",
                "path": f.path("safe/new.txt").to_string_lossy(),
                "content": "x"
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("writes_not_permitted"));
        assert!(!f.path("safe/new.txt").exists());
    }

    #[tokio::test]
    async fn a_writable_tool_writes_inside_the_sandbox() {
        let f = Fixture::new("write");
        let outcome = f
            .tool()
            .writable()
            .execute(json!({
                "operation": "write",
                "path": f.path("safe/new.txt").to_string_lossy(),
                "content": "written"
            }))
            .await
            .unwrap();

        assert!(outcome.success);
        assert_eq!(
            std::fs::read_to_string(f.path("safe/new.txt")).unwrap(),
            "written"
        );
    }

    #[tokio::test]
    async fn a_writable_tool_still_cannot_write_outside() {
        let f = Fixture::new("write_out");
        let err = f
            .tool()
            .writable()
            .execute(json!({
                "operation": "write",
                "path": f.path("escaped.txt").to_string_lossy(),
                "content": "x"
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
        assert!(!f.path("escaped.txt").exists());
    }

    #[tokio::test]
    async fn reads_are_capped_and_report_truncation() {
        let f = Fixture::new("cap");
        std::fs::write(f.path("safe/big.txt"), vec![b'x'; 10_000]).unwrap();

        let outcome = f
            .tool()
            .with_read_limit(1000)
            .execute(json!({"operation": "read", "path": f.path("safe/big.txt").to_string_lossy()}))
            .await
            .unwrap();

        assert_eq!(outcome.content.as_ref().unwrap().len(), 1000);
        assert_eq!(outcome.summary["truncated"], json!(true));
        assert_eq!(outcome.summary["file_bytes"], json!(10_000));
        // The digest must describe what was returned, not what was on disk.
        assert_eq!(
            outcome.summary["sha256"],
            json!(sha256_hex(&vec![b'x'; 1000]))
        );
    }

    #[tokio::test]
    async fn the_summary_never_contains_file_contents() {
        let f = Fixture::new("summary");
        std::fs::write(f.path("safe/s.txt"), "TOP_SECRET_VALUE").unwrap();

        let outcome = f
            .tool()
            .execute(json!({"operation": "read", "path": f.path("safe/s.txt").to_string_lossy()}))
            .await
            .unwrap();

        let summary = serde_json::to_string(&outcome.summary).unwrap();
        assert!(!summary.contains("TOP_SECRET_VALUE"), "{summary}");
        for value in outcome.metadata.values() {
            assert!(!value.contains("TOP_SECRET_VALUE"));
        }
    }

    #[tokio::test]
    async fn listing_returns_sorted_entries() {
        let f = Fixture::new("list");
        std::fs::write(f.path("safe/b.txt"), "").unwrap();
        std::fs::write(f.path("safe/a.txt"), "").unwrap();

        let outcome = f
            .tool()
            .execute(json!({"operation": "list", "path": f.path("safe").to_string_lossy()}))
            .await
            .unwrap();

        assert_eq!(outcome.summary["entries"], json!(["a.txt", "b.txt"]));
    }

    #[tokio::test]
    async fn listing_a_file_is_a_failed_outcome() {
        let f = Fixture::new("list_file");
        std::fs::write(f.path("safe/x.txt"), "").unwrap();

        let outcome = f
            .tool()
            .execute(json!({"operation": "list", "path": f.path("safe/x.txt").to_string_lossy()}))
            .await
            .unwrap();
        assert_eq!(outcome.error_code.as_deref(), Some("not_a_directory"));
    }

    #[tokio::test]
    async fn rejection_does_not_reveal_whether_the_path_exists() {
        // Both must give the same code, or a caller can map the filesystem.
        let f = Fixture::new("oracle");
        std::fs::write(f.path("real_outside.txt"), "x").unwrap();

        let exists = f
            .tool()
            .validate(
                &json!({"operation": "read", "path": f.path("real_outside.txt").to_string_lossy()}),
            )
            .await
            .unwrap_err()
            .to_string();
        let missing = f
            .tool()
            .validate(
                &json!({"operation": "read", "path": f.path("no_such_file.txt").to_string_lossy()}),
            )
            .await
            .unwrap_err()
            .to_string();

        assert_eq!(exists, missing);
    }

    #[tokio::test]
    async fn the_schema_hides_write_when_read_only() {
        let f = Fixture::new("schema");
        let read_only = f.tool().parameters_schema();
        assert_eq!(
            read_only["properties"]["operation"]["enum"],
            json!(["read", "list", "stat", "search", "glob", "exists"])
        );

        let writable = f.tool().writable().parameters_schema();
        assert_eq!(
            writable["properties"]["operation"]["enum"],
            json!([
                "read", "write", "list", "mkdir", "delete", "stat", "copy", "move", "append",
                "search", "glob", "patch", "exists"
            ])
        );
    }

    #[tokio::test]
    async fn glob_finds_matching_files() {
        let f = Fixture::new("glob");
        std::fs::write(f.path("safe/a.txt"), "").unwrap();
        std::fs::write(f.path("safe/b.txt"), "").unwrap();
        std::fs::write(f.path("safe/c.rs"), "").unwrap();
        let out = f
            .tool()
            .writable()
            .execute(json!({"operation":"glob","path": f.path("safe").to_string_lossy(), "pattern":"*.txt"}))
            .await
            .unwrap();
        assert!(out.success);
        assert_eq!(out.summary["count"], json!(2));
        let matches = out.summary["matches"].as_array().unwrap();
        assert!(matches
            .iter()
            .any(|v| v.as_str().unwrap().ends_with("a.txt")));
    }

    #[tokio::test]
    async fn patch_replaces_content() {
        let f = Fixture::new("patch");
        std::fs::write(f.path("safe/file.txt"), "hello world").unwrap();
        let out = f
            .tool()
            .writable()
            .execute(json!({"operation":"patch","path": f.path("safe/file.txt").to_string_lossy(), "search":"world","replace":"Rust"}))
            .await
            .unwrap();
        assert!(out.success);
        assert_eq!(out.summary["changed"], json!(true));
        assert_eq!(
            std::fs::read_to_string(f.path("safe/file.txt")).unwrap(),
            "hello Rust"
        );
    }

    #[tokio::test]
    async fn patch_fails_if_search_not_found() {
        let f = Fixture::new("patch_fail");
        std::fs::write(f.path("safe/file.txt"), "hello").unwrap();
        let out = f
            .tool()
            .writable()
            .execute(json!({"operation":"patch","path": f.path("safe/file.txt").to_string_lossy(), "search":"missing","replace":"x"}))
            .await
            .unwrap();
        assert!(!out.success);
        assert_eq!(out.error_code.as_deref(), Some("search_not_found"));
    }

    #[tokio::test]
    async fn stat_returns_metadata() {
        let f = Fixture::new("stat");
        std::fs::write(f.path("safe/file.txt"), "12345").unwrap();
        let out = f
            .tool()
            .execute(json!({"operation":"stat","path": f.path("safe/file.txt").to_string_lossy()}))
            .await
            .unwrap();
        assert!(out.success);
        assert_eq!(out.summary["is_file"], json!(true));
        assert_eq!(out.summary["len"], json!(5));
    }
}
