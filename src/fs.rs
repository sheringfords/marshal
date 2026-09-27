//! Reading, writing, and listing inside a sandbox.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};
#[allow(unused_imports)]
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tracing::debug;

use crate::sandbox::{BoundDir, BoundError, Sandbox, SandboxError};
use crate::{sha256_hex, Tool, ToolOutcome};

// POSIX file-type bits for interpreting `stat` results (see sandbox.rs).
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Wrap an owned descriptor as an async file handle. Dropping the handle
/// releases the descriptor, including on task cancellation.
fn tokio_file_from_fd(fd: rustix::fd::OwnedFd) -> tokio::fs::File {
    tokio::fs::File::from_std(std::fs::File::from(fd))
}

/// Drive buffered writes to the kernel (read-your-writes).
///
/// tokio's `File` acknowledges `write_all` once bytes reach its in-memory
/// buffer; the kernel write runs on a spawned task. Awaiting `flush` here
/// guarantees the bytes are kernel-visible before success is reported.
async fn file_flush(file: &mut tokio::fs::File) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    file.flush().await
}

/// Convert a rustix errno into the std error the outcome mappers expect.
/// Shapes are preserved with the pathname implementation: missing →
/// `not_found`, permission problems → `permission_denied`, directories where
/// files belong → `is_a_directory`, everything else → `io_error`.
fn std_io_error(e: rustix::io::Errno) -> std::io::Error {
    use rustix::io::Errno as E;
    let kind = match e {
        E::NOENT => std::io::ErrorKind::NotFound,
        E::PERM | E::ACCESS => std::io::ErrorKind::PermissionDenied,
        E::INVAL => std::io::ErrorKind::InvalidInput,
        E::ISDIR => std::io::ErrorKind::IsADirectory,
        _ => std::io::ErrorKind::Other,
    };
    std::io::Error::new(kind, format!("{e:?}"))
}

/// `(is_file, is_dir, len, readonly)` for the `stat` outcome summary.
fn stat_summary(st: &rustix::fs::Stat) -> (bool, bool, u64, bool) {
    let mode = st.st_mode as u32;
    (
        mode & S_IFMT == S_IFREG,
        mode & S_IFMT == S_IFDIR,
        st.st_size.max(0) as u64,
        mode & 0o222 == 0,
    )
}

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

/// Session scope state carried in tool args under the reserved key.
///
/// The server strips caller-supplied values before admission and injects
/// the canonical root from its own session table, so a well-formed value
/// is authoritative for server-mediated execution. Direct library callers
/// (experiment harness, bins, tests) normally omit the key and get plain
/// workspace-sandbox behavior — the documented trusted-local contract.
/// A *present but malformed* value (non-string, or a non-absolute path
/// the server could never have sent) fails closed: it signals forgery or
/// a broken intermediary, and must never read as "no restriction".
#[derive(Debug, PartialEq)]
enum Scope {
    /// No key: workspace-sandbox behavior (server session-less calls and
    /// direct library use).
    None,
    /// Absolute session root: narrow containment to it.
    Root(std::path::PathBuf),
    /// Present but malformed: deny everything.
    Malformed,
}

/// Substring search over a descriptor-retained traversal.
///
/// `display_base` renders match paths exactly as the pathname walk did; all
/// I/O goes through retained descriptors. Directory symlinks are never
/// descended (matching the old `d_type`-gated walk); file symlinks are opened
/// verified, so only links landing inside contribute content.
async fn search_fd(
    bound: &BoundDir,
    rel: &Path,
    display_base: &Path,
    pat: &str,
    recursive: bool,
    read_limit: usize,
) -> Result<(Vec<Value>, usize), BoundError> {
    // Open the base: a directory base walks, a file base greps once.
    let base_dir = if rel.as_os_str().is_empty() {
        bound.try_clone()?
    } else {
        match bound.descend_verified(rel) {
            Ok(dir) => dir,
            Err(BoundError::Unresolvable) => {
                // Maybe a file base: verify-open and grep it alone.
                let (parent, leaf) = bound.split_parent(rel)?;
                let leaf = leaf.ok_or(BoundError::Unresolvable)?;
                let (fd, _) =
                    parent.open_file_verified(leaf.as_os_str(), rustix::fs::OFlags::RDONLY)?;
                return search_single_file(&fd, display_base, pat, read_limit).await;
            }
            Err(e) => return Err(e),
        }
    };
    let mut matches = Vec::new();
    let mut count = 0usize;
    let mut stack: Vec<(BoundDir, PathBuf)> = vec![(base_dir, display_base.to_path_buf())];
    while let Some((dir, display)) = stack.pop() {
        let entries = dir.read_dir()?;
        for entry in entries {
            let entry = entry
                .map_err(|e| std_io_error_other(&e))
                .map_err(BoundError::Io)?;
            let name_os = entry.file_name().to_string_lossy().into_owned();
            let name = std::ffi::OsStr::new(&name_os);
            let display_path = display.join(&name_os);
            match entry.file_type() {
                rustix::fs::FileType::Directory => {
                    if recursive {
                        if let Ok(child) = dir.descend_verified(Path::new(name)) {
                            stack.push((child, display_path));
                        }
                    }
                }
                rustix::fs::FileType::RegularFile => {
                    if let Ok((fd, _)) = dir.open_file_verified(name, rustix::fs::OFlags::RDONLY) {
                        grep_fd_stream(
                            &fd,
                            &display_path,
                            pat,
                            read_limit,
                            &mut matches,
                            &mut count,
                        )
                        .await;
                    }
                    if count >= 1000 {
                        break;
                    }
                }
                rustix::fs::FileType::Symlink => {
                    // Files only, verified inside; symlinked dirs are never
                    // descended (as before).
                    if let Ok((fd, _)) = dir.open_file_verified(name, rustix::fs::OFlags::RDONLY) {
                        if let Ok(st) = rustix::fs::fstat(&fd) {
                            if st.st_mode as u32 & S_IFMT == S_IFREG {
                                grep_fd_stream(
                                    &fd,
                                    &display_path,
                                    pat,
                                    read_limit,
                                    &mut matches,
                                    &mut count,
                                )
                                .await;
                            }
                        }
                    }
                    if count >= 1000 {
                        break;
                    }
                }
                _ => {
                    // Unknown type (odd filesystems): try directory first,
                    // then a verified file read; either may fail closed.
                    if recursive {
                        if let Ok(child) = dir.descend_verified(Path::new(name)) {
                            stack.push((child, display_path.clone()));
                            continue;
                        }
                    }
                    if let Ok((fd, _)) = dir.open_file_verified(name, rustix::fs::OFlags::RDONLY) {
                        grep_fd_stream(
                            &fd,
                            &display_path,
                            pat,
                            read_limit,
                            &mut matches,
                            &mut count,
                        )
                        .await;
                    }
                    if count >= 1000 {
                        break;
                    }
                }
            }
            if count >= 1000 {
                break;
            }
        }
        if count >= 1000 {
            break;
        }
    }
    Ok((matches, count))
}

/// Grep one open file for `pat`, pushing matches in the historical shape.
async fn grep_fd_stream(
    fd: &rustix::fd::OwnedFd,
    display_path: &Path,
    pat: &str,
    read_limit: usize,
    matches: &mut Vec<Value>,
    count: &mut usize,
) {
    let Ok(clone) = fd.try_clone() else {
        return;
    };
    let std_file = std::fs::File::from(clone);
    let Ok(meta) = std_file.metadata() else {
        return;
    };
    if meta.len() > read_limit as u64 * 4 {
        return;
    }
    let file = tokio::fs::File::from_std(std_file);
    let Ok((bytes, _, _)) = read_capped_from_file(file, read_limit.min(1024 * 1024)).await else {
        return;
    };
    let content = String::from_utf8_lossy(&bytes);
    for (idx, line) in content.lines().enumerate() {
        if line.contains(pat) {
            matches.push(json!({"file": display_path.display().to_string(), "line": idx + 1, "text": line.chars().take(512).collect::<String>()}));
            *count += 1;
            if *count >= 1000 {
                break;
            }
        }
    }
}

/// Single-file search result wrapper (base was a file, not a directory).
async fn search_single_file(
    fd: &rustix::fd::OwnedFd,
    display_path: &Path,
    pat: &str,
    read_limit: usize,
) -> Result<(Vec<Value>, usize), BoundError> {
    let mut matches = Vec::new();
    let mut count = 0usize;
    grep_fd_stream(fd, display_path, pat, read_limit, &mut matches, &mut count).await;
    Ok((matches, count))
}

/// Glob matching over a descriptor-retained traversal.
///
/// Static segments descend verified (following only links that land inside,
/// as the pathname walk did); wildcard segments match entry names with the
/// same `glob::Pattern` rules. Final-segment symlinks are included only when
/// they verify inside. Results are display strings in sorted order.
/// Glob matching over a descriptor-retained traversal.
///
/// Static segments descend verified (following only links that land inside,
/// as the pathname walk did); wildcard segments match entry names with the
/// same `glob::Pattern` rules, descending only into verified directories.
/// Final-segment links are included only when they verify inside. Results are
/// display strings in sorted order, capped at 1000 like before.
fn glob_fd(
    bound: &BoundDir,
    rel: &Path,
    display_base: &Path,
    pattern: &str,
) -> Result<Vec<String>, BoundError> {
    let base = if rel.as_os_str().is_empty() {
        bound.try_clone()?
    } else {
        bound.descend_verified(rel)?
    };
    let mut out = Vec::new();
    glob_level(
        &base,
        display_base,
        &pattern.split('/').collect::<Vec<_>>(),
        &mut out,
    )?;
    out.sort();
    out.truncate(1000);
    Ok(out)
}

fn glob_level(
    dir: &BoundDir,
    display: &Path,
    segs: &[&str],
    out: &mut Vec<String>,
) -> Result<(), BoundError> {
    let Some((seg, rest)) = segs.split_first() else {
        return Ok(());
    };
    if *seg == "." || seg.is_empty() {
        return glob_level(dir, display, rest, out);
    }
    if seg.contains(['*', '?', '[']) {
        let pat = glob::Pattern::new(seg).map_err(|_| BoundError::Outside)?;
        let entries = dir.read_dir()?;
        for entry in entries {
            let entry = entry.map_err(|e| BoundError::Io(std_io_error_other(&e)))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !pat.matches(&name) {
                continue;
            }
            let display_path = display.join(&name);
            if rest.is_empty() {
                if glob_final_ok(dir, &name)? {
                    out.push(display_path.display().to_string());
                }
            } else if let Ok(child) = dir.descend_verified(Path::new(name.as_str())) {
                glob_level(&child, &display_path, rest, out)?;
            }
        }
        return Ok(());
    }
    // Static segment: descend verified when it is a directory...
    if rest.is_empty() {
        if dir.descend_verified(Path::new(seg)).is_ok() {
            out.push(display.join(seg).display().to_string());
            return Ok(());
        }
        // ...else include it when it verifies as an in-root file or link.
        if glob_final_ok(dir, seg)? {
            out.push(display.join(seg).display().to_string());
        }
        return Ok(());
    }
    let child = dir.descend_verified(Path::new(seg))?;
    glob_level(&child, &display.join(seg), rest, out)
}

/// Whether a final-segment glob entry may be listed: directories by verified
/// descent, files and links by verified open (inside-only).
fn glob_final_ok(dir: &BoundDir, name: &str) -> Result<bool, BoundError> {
    use rustix::fs::FileType;
    let entries = dir.read_dir()?;
    for entry in entries {
        let entry = entry.map_err(|e| BoundError::Io(std_io_error_other(&e)))?;
        if entry.file_name().to_string_lossy() != name {
            continue;
        }
        match entry.file_type() {
            FileType::Directory => {
                return Ok(dir.descend_verified(Path::new(name)).is_ok());
            }
            FileType::RegularFile | FileType::Symlink => {
                return Ok(dir
                    .open_file_verified(std::ffi::OsStr::new(name), rustix::fs::OFlags::RDONLY)
                    .is_ok());
            }
            _ => {
                if dir.descend_verified(Path::new(name)).is_ok() {
                    return Ok(true);
                }
                return Ok(dir
                    .open_file_verified(std::ffi::OsStr::new(name), rustix::fs::OFlags::RDONLY)
                    .is_ok());
            }
        }
    }
    Ok(false)
}

/// Wrap any debug-printable error as a std I/O error (directory iteration
/// yields backend error types on some platforms).
fn std_io_error_other(e: &impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("{e:?}"))
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
        match Self::scope_state(args) {
            Scope::Root(p) => Some(p),
            _ => None,
        }
    }

    fn scope_state(args: &Value) -> Scope {
        let Some(v) = args.get(crate::server::SESSION_SCOPE_KEY) else {
            return Scope::None;
        };
        match v.as_str() {
            Some(s) if std::path::PathBuf::from(s).is_absolute() => {
                Scope::Root(std::path::PathBuf::from(s))
            }
            _ => Scope::Malformed,
        }
    }

    /// Fail closed on a malformed scope before any path is touched.
    fn check_scope_wellformed(args: &Value) -> Result<()> {
        if Self::scope_state(args) == Scope::Malformed {
            anyhow::bail!("path_not_allowed");
        }
        Ok(())
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

    /// Bind the containing root for an already-resolved canonical path and
    /// return the descriptor plus the root-relative remainder.
    ///
    /// The root is the session root when one is bound, else the sandbox root
    /// containing the path. Binding opens the root directory *now*, so every
    /// later step operates on descriptors that cannot be swapped out from
    /// under the operation — unlike the pathname `resolved`, which is only
    /// used to derive the relative remainder. A bind failure after a
    /// successful resolve means the root vanished mid-operation: fail closed.
    fn bind_for(
        &self,
        args: &Value,
        resolved: &std::path::Path,
    ) -> Result<(BoundDir, std::path::PathBuf)> {
        let roots: Vec<std::path::PathBuf> = if let Some(scope) = Self::scope_root(args) {
            vec![scope]
        } else {
            self.sandbox.roots().to_vec()
        };
        let root = roots
            .iter()
            .find(|r| resolved.starts_with(r))
            .ok_or_else(|| anyhow::anyhow!("path_not_allowed"))?;
        let rel = resolved
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("path_not_allowed"))?
            .to_path_buf();
        let bound = BoundDir::bind(root).map_err(|_| anyhow::anyhow!("path_not_allowed"))?;
        Ok((bound, rel))
    }

    /// Map a descriptor-layer failure onto the tool's error shapes.
    ///
    /// These steps run after the sandbox resolve already classified the path,
    /// so any failure here crossed a race (vanished root, swapped component,
    /// revoked permission): fail closed with `path_not_allowed`, exactly the
    /// shape the resolve itself produces. Genuine I/O on already-open files
    /// keeps its `io_code` outcome mapping at each call site instead.
    fn bound_policy_error(e: BoundError) -> anyhow::Error {
        let _ = e;
        anyhow::anyhow!("path_not_allowed")
    }

    /// Recursive `mkdir -p` through retained descriptors.
    ///
    /// Missing levels are created with `mkdirat` and re-opened verified;
    /// existing levels are descended verified (following only links that land
    /// inside the root). A trailing symlink is never traversed: it fails
    /// closed, where the pathname implementation followed it. An existing
    /// non-directory at any level surfaces as an I/O error so the caller can
    /// keep the `create_dir_all` outcome shape.
    fn mkdir_fd(&self, bound: BoundDir, rel: &std::path::Path) -> Result<(), BoundError> {
        if rel.as_os_str().is_empty() {
            return Ok(());
        }
        let comps: Vec<std::ffi::OsString> = rel
            .components()
            .map(|c| c.as_os_str().to_os_string())
            .collect();
        let mut current = bound;
        for comp in comps.iter() {
            match current.descend_verified(std::path::Path::new(comp)) {
                Ok(next) => {
                    current = next;
                    continue;
                }
                Err(BoundError::Unresolvable) => {}
                Err(e) => return Err(e),
            }
            // Missing: what stands in the way decides the shape.
            match current.stat_leaf(comp.as_os_str()) {
                Ok(st) if st.st_mode as u32 & S_IFMT == S_IFDIR => {
                    current = current.descend_verified(std::path::Path::new(comp))?;
                    continue;
                }
                Ok(_) => {
                    // A file (or link) where a directory must go: mirror the
                    // `create_dir_all` I/O failure, not a rejection.
                    return Err(BoundError::Io(std::io::Error::other("not a directory")));
                }
                Err(BoundError::Unresolvable) => {}
                Err(e) => return Err(e),
            }
            current.mkdir(comp.as_os_str())?;
            current = current.descend_verified(std::path::Path::new(comp))?;
        }
        Ok(())
    }
}

/// Recursively remove a directory tree through retained descriptors.
///
/// Every level is descended through verified directory descriptors and every
/// entry unlinked by name from its pinned parent, so a swapped intermediate
/// cannot redirect the removal outside the tree. Returns `Ok` when the tree
/// is gone.
fn remove_dir_fd(dir: &BoundDir) -> Result<(), BoundError> {
    use std::os::unix::ffi::OsStrExt;
    let entries = dir.read_dir()?;
    for entry in entries {
        let entry = entry.map_err(|e| BoundError::Io(std_io_error_other(&e)))?;
        let name = entry.file_name().to_bytes();
        let name = std::ffi::OsStr::from_bytes(name);
        // Classify without following: links are unlinked, never traversed.
        let st = rustix::fs::statat(
            dir.as_fd(),
            Path::new(name),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(map_bound_open_error)?;
        if st.st_mode as u32 & S_IFMT == S_IFDIR {
            let child = dir.descend_verified(Path::new(name))?;
            remove_dir_fd(&child)?;
            dir.unlink_dir(name)?;
        } else {
            dir.unlink_file(name)?;
        }
    }
    Ok(())
}

/// Map an `openat`-family errno for entry classification.
fn map_bound_open_error(e: rustix::io::Errno) -> BoundError {
    match e {
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR => BoundError::Unresolvable,
        rustix::io::Errno::LOOP
        | rustix::io::Errno::PERM
        | rustix::io::Errno::ACCESS
        | rustix::io::Errno::XDEV => BoundError::Outside,
        _ => BoundError::Io(std_io_error(e)),
    }
}

/// Where a symlink leaf points, for the `exists` probe.
enum LinkTarget {
    Inside,
    Absent,
    Outside,
}

/// Resolve a symlink leaf against its pinned parent's true path: landing
/// inside the effective roots reads `Inside`, a dangling or otherwise
/// unresolvable target reads `Absent` (reported absent, as before), and an
/// escaping target reads `Outside` (denied, as before). Only `readlink` runs
/// here — no I/O follows the link.
fn exists_link_target(parent: &BoundDir, leaf: &std::ffi::OsStr, roots: &[PathBuf]) -> LinkTarget {
    use std::os::unix::ffi::OsStringExt;
    let target = match rustix::fs::readlinkat(parent.as_fd(), Path::new(leaf), Vec::new()) {
        Ok(t) => PathBuf::from(std::ffi::OsString::from_vec(t.into_bytes())),
        Err(_) => return LinkTarget::Absent,
    };
    let joined = if target.is_absolute() {
        target
    } else {
        match parent.true_path() {
            Some(base) => base.join(target),
            None => return LinkTarget::Outside,
        }
    };
    match joined.canonicalize() {
        Ok(c) if roots.iter().any(|r| c.starts_with(r)) => LinkTarget::Inside,
        Ok(_) => LinkTarget::Outside,
        Err(_) => LinkTarget::Absent,
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
        // A forged or corrupted scope key denies everything up front: a
        // malformed scope must never read as "no restriction".
        Self::check_scope_wellformed(args)?;
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
                // Classification first (workspace + scope, canonical), then
                // the bytes come from a verified descriptor: trailing links
                // are followed only through open-then-verify, and a swap
                // after authorization cannot redirect the open file.
                let resolved = self.resolve_scoped_existing(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let (parent, leaf) = bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                let open = match leaf {
                    Some(leaf) => parent
                        .open_file_verified(leaf.as_os_str(), rustix::fs::OFlags::RDONLY)
                        .map_err(Self::bound_policy_error),
                    // Directories cannot be opened below; the outcome shape
                    // below reports them exactly as the pathname path did.
                    None => Err(anyhow::anyhow!("is_a_directory_open")),
                };
                let read_result = match open {
                    Ok((fd, _)) => {
                        read_capped_from_file(tokio_file_from_fd(fd), self.read_limit).await
                    }
                    Err(e) if e.to_string() == "is_a_directory_open" => Err(std::io::Error::new(
                        std::io::ErrorKind::IsADirectory,
                        "is a directory",
                    )),
                    Err(e) => return Err(e),
                };
                match read_result {
                    Err(e) => Ok::<ToolOutcome, anyhow::Error>(ToolOutcome::failure(
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
                }
            }

            "write" => {
                let resolved = self.resolve_scoped_for_create(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let (parent, leaf) = bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                // A trailing symlink is never traversed for a create target:
                // an existing link fails closed (the documented
                // `resolve_for_create` policy, enforced structurally here).
                let bytes: Vec<u8> = if let Some(s) = args.get("content").and_then(Value::as_str) {
                    s.as_bytes().to_vec()
                } else if let Some(b64) = args.get("content_base64").and_then(Value::as_str) {
                    BASE64
                        .decode(b64)
                        .map_err(|_| anyhow::anyhow!("invalid_base64"))?
                } else {
                    anyhow::bail!("missing 'content'");
                };

                let Some(leaf) = leaf else {
                    return Err(anyhow::anyhow!("path_not_allowed"));
                };
                let fd = parent
                    .open_file_nofollow(
                        leaf.as_os_str(),
                        rustix::fs::OFlags::WRONLY
                            | rustix::fs::OFlags::CREATE
                            | rustix::fs::OFlags::TRUNC,
                        rustix::fs::Mode::from_bits_truncate(0o644),
                    )
                    .map_err(Self::bound_policy_error)?;
                let mut file = tokio_file_from_fd(fd);
                // `write_all` only accepts bytes into tokio's in-memory
                // buffer (the kernel write runs on a spawned task): flush
                // before reporting success so a subsequent read observes the
                // write. Without this, success + immediate read races the
                // background task under load (observed as empty files).
                let write_outcome = match file.write_all(&bytes).await {
                    Ok(()) => file.flush().await,
                    Err(e) => Err(e),
                };
                match write_outcome {
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
                let resolved = self.resolve_scoped_for_create(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                // Every level is created or re-opened through retained
                // descriptors: a swapped intermediate cannot redirect the new
                // directory elsewhere. A trailing symlink is never traversed.
                let mkdir_outcome = match self.mkdir_fd(bound, &rel) {
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "mkdir", "path": resolved.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "mkdir")),
                    Err(BoundError::Outside) => Err(anyhow::anyhow!("path_not_allowed")),
                    Err(BoundError::Unresolvable) => Ok(ToolOutcome::failure(
                        "filesystem",
                        "not_found",
                        elapsed(started),
                    )),
                    Err(BoundError::Io(e)) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                };
                mkdir_outcome
            }

            "stat" => {
                let resolved = self.resolve_scoped_existing(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let (parent, leaf) = bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                // Open-then-stat follows trailing links exactly like
                // `metadata` did, but the verified descriptor cannot be
                // swapped afterwards.
                let stat_result = match leaf {
                    Some(leaf) => {
                        let (fd, _) = parent
                            .open_file_verified(leaf.as_os_str(), rustix::fs::OFlags::RDONLY)
                            .map_err(Self::bound_policy_error)?;
                        rustix::fs::fstat(&fd).map_err(std_io_error)
                    }
                    None => rustix::fs::fstat(parent.as_fd()).map_err(std_io_error),
                };
                match stat_result {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(st) => {
                        let (is_file, is_dir, len, readonly) = stat_summary(&st);
                        Ok(ToolOutcome::success(
                            "filesystem",
                            json!({
                                "operation": "stat",
                                "path": resolved.display().to_string(),
                                "is_file": is_file,
                                "is_dir": is_dir,
                                "len": len,
                                "readonly": readonly,
                            }),
                            elapsed(started),
                        )
                        .with_metadata("operation", "stat"))
                    }
                }
            }

            "copy" => {
                let resolved_src = self.resolve_scoped_existing(&args, raw)?;
                let dest_raw = args
                    .get("destination")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'destination'"))?;
                let resolved_dest = self.resolve_scoped_for_create(&args, dest_raw)?;
                let (src_bound, src_rel) = self.bind_for(&args, &resolved_src)?;
                let (dst_bound, dst_rel) = self.bind_for(&args, &resolved_dest)?;
                let (src_parent, src_leaf) = src_bound
                    .split_parent(&src_rel)
                    .map_err(Self::bound_policy_error)?;
                let (dst_parent, dst_leaf) = dst_bound
                    .split_parent(&dst_rel)
                    .map_err(Self::bound_policy_error)?;
                // Open the source verified (trailing links allowed exactly
                // when they land inside, as before) and the destination
                // never-followed (an existing link fails closed rather than
                // redirecting the copy into it).
                let Some(src_leaf) = src_leaf else {
                    return Err(anyhow::anyhow!("path_not_allowed"));
                };
                let Some(dst_leaf) = dst_leaf else {
                    return Err(anyhow::anyhow!("path_not_allowed"));
                };
                let (src_fd, _) = src_parent
                    .open_file_verified(src_leaf.as_os_str(), rustix::fs::OFlags::RDONLY)
                    .map_err(Self::bound_policy_error)?;
                let src_stat = rustix::fs::fstat(&src_fd).map_err(std_io_error)?;
                let dst_fd = dst_parent
                    .open_file_nofollow(
                        dst_leaf.as_os_str(),
                        rustix::fs::OFlags::WRONLY
                            | rustix::fs::OFlags::CREATE
                            | rustix::fs::OFlags::TRUNC,
                        rustix::fs::Mode::from_bits_truncate(0o644),
                    )
                    .map_err(Self::bound_policy_error)?;
                // ensure src and dest are not same (device + inode: the
                // descriptors cannot be swapped after opening)
                let dst_stat = rustix::fs::fstat(&dst_fd).map_err(std_io_error)?;
                if src_stat.st_dev == dst_stat.st_dev && src_stat.st_ino == dst_stat.st_ino {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "same_file",
                        elapsed(started),
                    ));
                }
                let mut src_file = tokio_file_from_fd(src_fd);
                let mut dst_file = tokio_file_from_fd(dst_fd);
                // Flush before success (see "write"): `copy` returns after
                // the last buffered acceptance, so drive completion first.
                let copy_outcome = match tokio::io::copy(&mut src_file, &mut dst_file).await {
                    Ok(n) => file_flush(&mut dst_file).await.map(|()| n),
                    Err(e) => Err(e),
                };
                match copy_outcome {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(n) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "copy", "bytes": n, "src": resolved_src.display().to_string(), "dest": resolved_dest.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "copy")),
                }
            }

            "move" => {
                let resolved_src = self.resolve_scoped_existing(&args, raw)?;
                let dest_raw = args
                    .get("destination")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'destination'"))?;
                let resolved_dest = self.resolve_scoped_for_create(&args, dest_raw)?;
                let (src_bound, src_rel) = self.bind_for(&args, &resolved_src)?;
                let (dst_bound, dst_rel) = self.bind_for(&args, &resolved_dest)?;
                let (src_parent, src_leaf) = src_bound
                    .split_parent(&src_rel)
                    .map_err(Self::bound_policy_error)?;
                let (dst_parent, dst_leaf) = dst_bound
                    .split_parent(&dst_rel)
                    .map_err(Self::bound_policy_error)?;
                // Refuse to move the effective root itself.
                let (Some(src_leaf), Some(dst_leaf)) = (src_leaf, dst_leaf) else {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "refused_move_root",
                        elapsed(started),
                    ));
                };
                // A trailing symlink at the destination is never followed, so
                // refuse it to match the create-target policy; either end
                // swapped mid-operation stays inside its pinned parent
                // regardless. NOTE: a symlink *source* is renamed as a link
                // here, while the pathname implementation followed it and
                // moved the target. Renaming the link is the POSIX `mv`
                // semantic and cannot escape the pinned parent; the old
                // behavior is recorded in the M2-003 report.
                if let Ok(dst_st) = dst_parent.stat_leaf(dst_leaf.as_os_str()) {
                    if dst_st.st_mode as u32 & S_IFMT == S_IFLNK {
                        return Err(anyhow::anyhow!("path_not_allowed"));
                    }
                }
                match src_parent.rename(
                    src_leaf.as_os_str(),
                    &dst_parent,
                    dst_leaf.as_os_str(),
                ) {
                    Err(BoundError::Outside | BoundError::Unresolvable) => {
                        Err(anyhow::anyhow!("path_not_allowed"))
                    }
                    Err(BoundError::Io(e)) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "move", "src": resolved_src.display().to_string(), "dest": resolved_dest.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "move")),
                }
            }

            "append" => {
                let resolved = self.resolve_scoped_for_create(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let (parent, leaf) = bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                let Some(leaf) = leaf else {
                    return Err(anyhow::anyhow!("path_not_allowed"));
                };
                let bytes: Vec<u8> = if let Some(s) = args.get("content").and_then(Value::as_str) {
                    s.as_bytes().to_vec()
                } else if let Some(b64) = args.get("content_base64").and_then(Value::as_str) {
                    BASE64
                        .decode(b64)
                        .map_err(|_| anyhow::anyhow!("invalid_base64"))?
                } else {
                    anyhow::bail!("missing 'content'");
                };
                // O_APPEND on the retained descriptor: atomic position, no
                // read-modify-write window and no lost concurrent appends.
                let fd = parent
                    .open_file_nofollow(
                        leaf.as_os_str(),
                        rustix::fs::OFlags::WRONLY
                            | rustix::fs::OFlags::CREATE
                            | rustix::fs::OFlags::APPEND,
                        rustix::fs::Mode::from_bits_truncate(0o644),
                    )
                    .map_err(Self::bound_policy_error)?;
                let mut file = tokio_file_from_fd(fd);
                // Flush before success (see "write"): read-your-writes.
                let write_outcome = match file.write_all(&bytes).await {
                    Ok(()) => file.flush().await,
                    Err(e) => Err(e),
                };
                match write_outcome {
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
                let resolved = self.resolve_scoped_existing(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let pattern = args.get("pattern").and_then(Value::as_str).unwrap_or("");
                let recursive = args
                    .get("recursive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                // Simple substring search, not regex, to avoid ReDoS.
                let pat = pattern.to_string();
                let (matches, count) =
                    search_fd(&bound, &rel, &resolved, &pat, recursive, self.read_limit)
                        .await
                        .map_err(|e| match e {
                            BoundError::Outside | BoundError::Unresolvable => {
                                anyhow::anyhow!("path_not_allowed")
                            }
                            BoundError::Io(io) => anyhow::anyhow!("{}", io_code(&io)),
                        })?;
                Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "search", "pattern": pat, "matches": matches, "count": count}),
                    elapsed(started),
                )
                .with_metadata("operation", "search"))
            }

            "glob" => {
                let resolved = self.resolve_scoped_existing(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let pattern = args.get("pattern").and_then(Value::as_str).unwrap_or("*");
                // Matching runs over retained descriptors; the pattern rules
                // (length cap, no `..`, no leading `/`) are unchanged from
                // validation.
                let matches = glob_fd(&bound, &rel, &resolved, pattern).map_err(|e| match e {
                    BoundError::Outside | BoundError::Unresolvable => {
                        anyhow::anyhow!("path_not_allowed")
                    }
                    BoundError::Io(io) => anyhow::anyhow!("{}", io_code(&io)),
                })?;
                Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "glob", "pattern": pattern, "matches": matches, "count": matches.len()}),
                    elapsed(started),
                )
                .with_metadata("operation", "glob"))
            }

            "patch" => {
                let resolved = self.resolve_scoped_existing(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let (parent, leaf) = bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                // Open verified read/write: trailing links are followed only
                // when they land inside (as before), and the same descriptor
                // is read, truncated and rewritten — never reopened by name.
                let Some(leaf) = leaf else {
                    return Err(anyhow::anyhow!("path_not_allowed"));
                };
                let (fd, _) = parent
                    .open_file_verified(leaf.as_os_str(), rustix::fs::OFlags::RDWR)
                    .map_err(Self::bound_policy_error)?;
                let file = tokio_file_from_fd(fd);
                let search = args.get("search").and_then(Value::as_str).unwrap_or("");
                let replace = args.get("replace").and_then(Value::as_str).unwrap_or("");
                if search.is_empty() {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "search_empty",
                        elapsed(started),
                    ));
                }
                // Cap file size for patch: read at most the limit, then probe
                // one extra byte the way the capped reader reports truncation.
                let mut content = String::new();
                let mut capped = file.take(self.read_limit as u64);
                if capped.read_to_string(&mut content).await.is_err() {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "io_error",
                        elapsed(started),
                    ));
                }
                let mut extra = [0u8; 1];
                let truncated = capped.read(&mut extra).await.unwrap_or(0) > 0;
                // `take` borrows the file; reclaim it for the rewrite below.
                let mut file = capped.into_inner();
                if truncated {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "file_too_large",
                        elapsed(started),
                    ));
                }
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
                    if file.seek(std::io::SeekFrom::Start(0)).await.is_err() {
                        return Ok(ToolOutcome::failure(
                            "filesystem",
                            "io_error",
                            elapsed(started),
                        ));
                    }
                    // Flush before success (see "write"): read-your-writes.
                    let rewrite_ok = file.set_len(0).await.is_ok()
                        && file.write_all(new_content.as_bytes()).await.is_ok()
                        && file.flush().await.is_ok();
                    if !rewrite_ok {
                        return Ok(ToolOutcome::failure(
                            "filesystem",
                            "io_error",
                            elapsed(started),
                        ));
                    }
                }
                Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "patch", "changed": changed, "sha256": sha256_hex(new_content.as_bytes())}),
                    elapsed(started),
                )
                .with_metadata("operation", "patch"))
            }

            "delete" => {
                let resolved = self.resolve_scoped_existing(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                let (parent, leaf) = bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                // Refuse to delete the effective root itself.
                let Some(leaf) = leaf else {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "refused_delete_root",
                        elapsed(started),
                    ));
                };
                // Classify without following: links are unlinked, never
                // traversed; directories are removed recursively through
                // verified descriptors (see below), never by pathname.
                let is_dir = match parent.stat_leaf(leaf.as_os_str()) {
                    Ok(st) => st.st_mode as u32 & S_IFMT == S_IFDIR,
                    Err(BoundError::Outside | BoundError::Unresolvable) => {
                        return Err(anyhow::anyhow!("path_not_allowed"));
                    }
                    Err(BoundError::Io(e)) => {
                        return Ok(ToolOutcome::failure(
                            "filesystem",
                            io_code(&e),
                            elapsed(started),
                        ));
                    }
                };
                let removal = if is_dir {
                    match parent.descend_verified(std::path::Path::new(leaf.as_os_str())) {
                        Ok(dir) => {
                            remove_dir_fd(&dir).and_then(|()| parent.unlink_dir(leaf.as_os_str()))
                        }
                        Err(BoundError::Outside | BoundError::Unresolvable) => {
                            return Err(anyhow::anyhow!("path_not_allowed"));
                        }
                        Err(BoundError::Io(e)) => {
                            return Ok(ToolOutcome::failure(
                                "filesystem",
                                io_code(&e),
                                elapsed(started),
                            ));
                        }
                    }
                } else {
                    parent.unlink_file(leaf.as_os_str())
                };
                match removal {
                    Err(BoundError::Outside | BoundError::Unresolvable) => {
                        Err(anyhow::anyhow!("path_not_allowed"))
                    }
                    Err(BoundError::Io(e)) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({"operation": "delete", "path": resolved.display().to_string()}),
                        elapsed(started),
                    )
                    .with_metadata("operation", "delete")),
                }
            }

            "list" => {
                let resolved = self.resolve_scoped_existing(&args, raw)?;
                let (bound, rel) = self.bind_for(&args, &resolved)?;
                // A file target lists nothing: probe the target type through
                // its parent first (before `bound` is consumed below) to
                // preserve the not_a_directory outcome.
                {
                    let (parent, leaf) =
                        bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                    if let Some(leaf) = leaf {
                        if let Ok(st) = parent.stat_leaf(leaf.as_os_str()) {
                            if st.st_mode as u32 & S_IFMT != S_IFDIR {
                                return Ok(ToolOutcome::failure(
                                    "filesystem",
                                    "not_a_directory",
                                    elapsed(started),
                                ));
                            }
                        }
                    }
                }
                // Open-then-verify follows a trailing link exactly when it
                // lands inside (as before); the names below come from the
                // open descriptor, so a swapped directory cannot inject
                // entries from elsewhere.
                let dir = if rel.as_os_str().is_empty() {
                    bound
                } else {
                    match bound.descend_verified(&rel) {
                        Ok(dir) => dir,
                        Err(BoundError::Outside | BoundError::Unresolvable) => {
                            return Err(anyhow::anyhow!("path_not_allowed"));
                        }
                        Err(BoundError::Io(e)) => {
                            return Ok(ToolOutcome::failure(
                                "filesystem",
                                io_code(&e),
                                elapsed(started),
                            ));
                        }
                    }
                };
                let entries = match dir.read_dir() {
                    Ok(entries) => entries,
                    Err(BoundError::Outside | BoundError::Unresolvable) => {
                        return Err(anyhow::anyhow!("path_not_allowed"));
                    }
                    Err(BoundError::Io(e)) => {
                        return Ok(ToolOutcome::failure(
                            "filesystem",
                            io_code(&e),
                            elapsed(started),
                        ));
                    }
                };
                let mut names = Vec::new();
                let mut read_error: Option<std::io::Error> = None;
                for entry in entries {
                    match entry {
                        Ok(entry) => {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            // Raw directory iteration yields `.` and `..`;
                            // `std::fs::read_dir` hides them, and so do we.
                            if name != "." && name != ".." {
                                names.push(name);
                            }
                        }
                        Err(e) => {
                            read_error = Some(e.into());
                            break;
                        }
                    }
                }
                if let Some(e) = read_error {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    ));
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

            "exists" => match self.sandbox.resolve_existing(raw) {
                Ok(p) => {
                    self.check_scope(&args, &p)?;
                    let (bound, rel) = self.bind_for(&args, &p)?;
                    let (parent, leaf) =
                        bound.split_parent(&rel).map_err(Self::bound_policy_error)?;
                    // Existence through descriptors: the root itself exists;
                    // links are resolved against the parent's true path and
                    // must land inside the effective roots (dangling links
                    // report absent, escaping links are denied, as before).
                    let exists = match leaf {
                        None => true,
                        Some(leaf) => {
                            use rustix::fs::AtFlags;
                            match rustix::fs::statat(
                                parent.as_fd(),
                                Path::new(leaf.as_os_str()),
                                AtFlags::SYMLINK_NOFOLLOW,
                            ) {
                                Ok(st) => {
                                    if st.st_mode as u32 & S_IFMT != S_IFLNK {
                                        true
                                    } else {
                                        match exists_link_target(
                                            &parent,
                                            leaf.as_os_str(),
                                            &self.effective_roots(&args),
                                        ) {
                                            LinkTarget::Inside => true,
                                            LinkTarget::Absent => false,
                                            LinkTarget::Outside => {
                                                return Err(anyhow::anyhow!("path_not_allowed"));
                                            }
                                        }
                                    }
                                }
                                Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => false,
                                Err(_) => {
                                    return Err(anyhow::anyhow!("path_not_allowed"));
                                }
                            }
                        }
                    };
                    Ok(ToolOutcome::success(
                    "filesystem",
                    json!({"operation": "exists", "exists": exists, "path": p.display().to_string()}),
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

/// Capped read from an already-open file handle. Shared by every platform
/// now that reads are descriptor-retained everywhere.
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

    // ── direct-caller scope contract (M2-003 gate) ────────────
    //
    // The server strips and re-injects the reserved scope key, so these cases
    // only arise for direct library callers. The contract: omitted key →
    // workspace behavior; absolute forged key → still confined to the tool
    // sandbox (forgery cannot widen past it, only narrow); malformed key →
    // deny everything.

    fn scoped_args(f: &Fixture, scope: &str, op: &str, rel: &str) -> Value {
        json!({
            "operation": op,
            "path": f.path(rel).to_string_lossy(),
            crate::server::SESSION_SCOPE_KEY: scope,
        })
    }

    #[tokio::test]
    async fn omitted_scope_keeps_workspace_behavior() {
        let f = Fixture::new("scope-omitted");
        std::fs::write(f.path("safe/a.txt"), "a").unwrap();
        let out = f
            .tool()
            .execute(json!({"operation":"read","path": f.path("safe/a.txt").to_string_lossy()}))
            .await
            .unwrap();
        assert!(out.success);
    }

    #[tokio::test]
    async fn forged_absolute_scope_cannot_widen_past_the_sandbox() {
        let f = Fixture::new("scope-forged");
        std::fs::create_dir_all(f.path("outside")).unwrap();
        std::fs::write(f.path("outside/secret.txt"), "secret").unwrap();
        std::fs::write(f.path("safe/ok.txt"), "ok").unwrap();
        // Forged "/" scope: sandbox backstop still denies outside-sandbox.
        let err = f
            .tool()
            .execute(scoped_args(&f, "/", "read", "outside/secret.txt"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
        // ... while in-sandbox reads still work (scope "/" contains all).
        let out = f
            .tool()
            .execute(scoped_args(&f, "/", "read", "safe/ok.txt"))
            .await
            .unwrap();
        assert!(out.success);
    }

    #[tokio::test]
    async fn forged_narrow_scope_narrows_even_for_direct_callers() {
        let f = Fixture::new("scope-narrow");
        std::fs::create_dir_all(f.path("safe/sub")).unwrap();
        std::fs::write(f.path("safe/top.txt"), "top").unwrap();
        std::fs::write(f.path("safe/sub/in.txt"), "in").unwrap();
        // Canonicalize: the scope check compares canonical paths, and the
        // fixture base may itself sit under a symlinked tmpdir.
        let sub = f
            .path("safe/sub")
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        // In-sandbox but outside the forged scope → denied.
        let err = f
            .tool()
            .execute(scoped_args(&f, &sub, "read", "safe/top.txt"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
        let out = f
            .tool()
            .execute(scoped_args(&f, &sub, "read", "safe/sub/in.txt"))
            .await
            .unwrap();
        assert!(out.success);
    }

    #[tokio::test]
    async fn malformed_scope_denies_everything() {
        let f = Fixture::new("scope-malformed");
        std::fs::write(f.path("safe/a.txt"), "a").unwrap();
        for scope in [
            json!("relative/path"),
            json!(""),
            json!(42),
            json!({"nested": "object"}),
        ] {
            let err = f
                .tool()
                .execute(json!({
                    "operation": "read",
                    "path": f.path("safe/a.txt").to_string_lossy(),
                    crate::server::SESSION_SCOPE_KEY: scope,
                }))
                .await
                .unwrap_err();
            assert!(err.to_string().contains("path_not_allowed"), "{scope}");
        }
    }
}
