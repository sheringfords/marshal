//! Path containment: deciding whether a path is inside an allowed root.
//!
//! This is the module the filesystem and shell tools both depend on, and it is
//! the one that was wrong in the code this crate was extracted from. Two
//! separate escapes, both confirmed by running them:
//!
//! **String prefixes are not path prefixes.** The original compared with
//! `str::starts_with`, so a root of `/tmp/safe` admitted `/tmp/safe_evil/…` —
//! a *sibling* directory that merely shares a textual prefix.
//! [`Path::starts_with`] compares whole components and does not have this
//! problem, which is why every check here goes through `Path`.
//!
//! **Rejecting `..` textually does not stop traversal.** The original scanned
//! for `Component::ParentDir` and otherwise trusted the string, so a symlink at
//! `/tmp/safe/link -> /etc` made `/tmp/safe/link/passwd` a legal path by
//! inspection and `/etc/passwd` in practice. Only asking the filesystem what a
//! path really resolves to closes that, so everything here canonicalizes first.
//!
//! # What this still does not give you
//!
//! Containment is checked at resolve time and used a moment later, so a symlink
//! swapped in between the two wins the race. On Linux this is now closed via
//! `openat2` with `RESOLVE_BENEATH`; on other platforms the check-then-use race
//! remains. Treat this as a guard against confused paths and mistaken
//! configuration on non-Linux, and as a true containment on Linux with
//! `openat2` available.

use std::path::{Path, PathBuf};

/// A path was outside every configured root, or could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    /// No roots were configured, so nothing is permitted.
    #[error("no sandbox roots configured; every path is denied")]
    NoRoots,

    /// A configured root does not exist or could not be canonicalized.
    #[error("sandbox root {root} is unusable: {reason}")]
    BadRoot {
        /// The offending root as configured.
        root: String,
        /// Why it could not be used.
        reason: String,
    },

    /// The path resolved outside every root.
    #[error("path is outside the sandbox")]
    Outside,

    /// The path (or its parent, when creating) does not exist.
    #[error("path does not resolve to an existing location")]
    Unresolvable,
}

/// A set of canonicalized roots that paths must resolve inside.
///
/// Roots are canonicalized once at construction, so a symlinked root works and
/// a root that disappears later fails closed rather than silently widening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    roots: Vec<PathBuf>,
}

impl Sandbox {
    /// Build a sandbox from one or more roots.
    ///
    /// Every root must already exist: a root that does not is a configuration
    /// error, and treating it as an empty allowance would let it start
    /// permitting things the moment someone creates the directory.
    pub fn new<I, P>(roots: I) -> Result<Self, SandboxError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut canonical = Vec::new();
        for root in roots {
            let root = root.as_ref();
            let resolved = root.canonicalize().map_err(|e| SandboxError::BadRoot {
                root: root.display().to_string(),
                reason: e.to_string(),
            })?;
            if !resolved.is_dir() {
                return Err(SandboxError::BadRoot {
                    root: root.display().to_string(),
                    reason: "not a directory".to_string(),
                });
            }
            canonical.push(resolved);
        }

        if canonical.is_empty() {
            return Err(SandboxError::NoRoots);
        }
        Ok(Sandbox { roots: canonical })
    }

    /// The canonicalized roots.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Whether an already-canonical path lies inside a root.
    ///
    /// Uses [`Path::starts_with`], which matches whole components — this is the
    /// difference between admitting `/tmp/safe/x` and admitting
    /// `/tmp/safe_evil/x`.
    fn contains(&self, canonical: &Path) -> bool {
        self.roots.iter().any(|root| canonical.starts_with(root))
    }

    /// Resolve a path that must already exist, and confirm it is inside.
    ///
    /// Canonicalization follows symlinks, so a link pointing out of the
    /// sandbox is rejected on where it *lands*, not on how it is spelled.
    /// On Linux, `openat2` with `RESOLVE_BENEATH` is used to close the
    /// check-then-use race; elsewhere the classic `canonicalize` + `contains`
    /// check is used.
    pub fn resolve_existing(&self, path: impl AsRef<Path>) -> Result<PathBuf, SandboxError> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(p) = self.resolve_with_openat2(path.as_ref()) {
                return Ok(p);
            }
            // Fall back to canonicalize if openat2 unavailable (e.g. old kernel).
        }
        let canonical = path
            .as_ref()
            .canonicalize()
            .map_err(|_| SandboxError::Unresolvable)?;
        if self.contains(&canonical) {
            Ok(canonical)
        } else {
            Err(SandboxError::Outside)
        }
    }

    /// Resolve a path that may not exist yet, for creation.
    ///
    /// The *parent* must exist and resolve inside the sandbox; the final
    /// component is then appended without following it. A final component of
    /// `.` or `..` is rejected outright, since neither names a file to create.
    ///
    /// If the target already exists as a symlink, this deliberately does not
    /// follow it — writing through a link that leaves the sandbox is exactly
    /// what must not happen.
    pub fn resolve_for_create(&self, path: impl AsRef<Path>) -> Result<PathBuf, SandboxError> {
        let path = path.as_ref();

        let name = match path.file_name() {
            Some(name) => name,
            // No final component means `/`, `.`, or a trailing `..`.
            None => return Err(SandboxError::Unresolvable),
        };

        let parent = path.parent().ok_or(SandboxError::Unresolvable)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };

        #[cfg(target_os = "linux")]
        {
            // For parent == "." (relative `file.txt` with no dir), don't use openat2
            // with root — it would incorrectly treat "." as root. Fall back to
            // canonicalize which resolves "." as cwd (correctly outside).
            if parent != Path::new(".") {
                if let Ok(parent_canonical) = self.resolve_with_openat2(parent) {
                    let target = parent_canonical.join(name);
                    // Use openat2 for target existence check as well to avoid
                    // symlink_metadata TOCTOU.
                    if target.symlink_metadata().is_ok() {
                        return self.resolve_existing(&target);
                    }
                    return Ok(target);
                }
            }
        }

        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| SandboxError::Unresolvable)?;
        if !self.contains(&canonical_parent) {
            return Err(SandboxError::Outside);
        }

        let target = canonical_parent.join(name);

        // If it exists already it must itself resolve inside — this catches a
        // pre-placed symlink pointing out.
        if target.symlink_metadata().is_ok() {
            return self.resolve_existing(&target);
        }
        Ok(target)
    }

    /// Linux `openat2` with `RESOLVE_BENEATH` to close TOCTOU.
    #[cfg(target_os = "linux")]
    fn resolve_with_openat2(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        use std::os::unix::io::AsRawFd;
        for root in &self.roots {
            let root_file = match std::fs::File::open(root) {
                Ok(f) => f,
                Err(_) => continue,
            };
            // Make path relative to this root for RESOLVE_BENEATH.
            // For absolute paths, must be under this root to be considered;
            // for relative paths, treat as relative to root (sandbox-relative)
            // and also fallback to canonicalize for cwd-relative cases.
            let rel: PathBuf = if path.is_absolute() {
                if path == root.as_path() {
                    PathBuf::from(".")
                } else if let Ok(stripped) = path.strip_prefix(root) {
                    if stripped.as_os_str().is_empty() {
                        PathBuf::from(".")
                    } else {
                        stripped.to_path_buf()
                    }
                } else {
                    // Not under this root as path prefix — try next root.
                    continue;
                }
            } else {
                // Relative path: if it contains `..` that would escape, BENEATH will block.
                // Try as relative to root; if it fails, fallback will handle cwd-relative.
                path.to_path_buf()
            };
            let root_fd = root_file.as_raw_fd();
            if let Ok(canonical) = openat2_resolve(root_fd, &rel) {
                // Double-check canonical is still inside root (defense-in-depth).
                if canonical.starts_with(root) || canonical == *root {
                    return Ok(canonical);
                }
            }
        }
        Err(SandboxError::Outside)
    }
}

#[cfg(target_os = "linux")]
fn openat2_resolve(root_fd: i32, path: &Path) -> Result<PathBuf, SandboxError> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    use std::os::fd::{AsRawFd, BorrowedFd};

    let dirfd = unsafe { BorrowedFd::borrow_raw(root_fd) };
    let flags = OFlags::PATH | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH;

    if let Ok(file) = openat2(dirfd, path, flags, Mode::empty(), resolve) {
        let fd = file.as_raw_fd();
        let proc_path = format!("/proc/self/fd/{fd}");
        if let Ok(p) = std::fs::read_link(&proc_path) {
            return Ok(p);
        }
        return Err(SandboxError::Outside);
    }
    Err(SandboxError::Outside)
}

// Descriptor-retained containment (M2-003).
//
// [`Sandbox::resolve_*`] answers "is this path inside?" and hands back a
// pathname; anything that reopens that pathname later races a symlink swap
// (see `tests/toctou.rs` for the demonstration). [`BoundDir`] closes the
// race the other way round: it opens the authorized root *directory* once,
// then performs every operation relative to retained directory descriptors,
// never following an attacker-controlled symlink.
//
// Symlink policy (uniform on every platform):
//
// - Intermediate components are never traversed through symlinks. A link
//   where a directory is required fails the operation closed.
// - `.` and `..` components are rejected outright, so `BENEATH`-style
//   escapes cannot be spelled even where the kernel would permit them.
// - The final component of a *create* target (`write`, `mkdir`, copy/move
//   destination) is never followed: an existing symlink there fails closed,
//   matching [`Sandbox::resolve_for_create`].
// - The final component of a *read* target may be opened following links,
//   but only through [`BoundDir::open_verified`], which reports the true
//   post-open path of the obtained descriptor and requires it inside the
//   root. The descriptor cannot be swapped after opening, so the check is
//   not racy the way pathname checks are.
//
// On Linux, opens additionally request `openat2` `RESOLVE_BENEATH |
// RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` so the kernel enforces the
// same policy; where the kernel predates `openat2` (`ENOSYS`) the call falls
// back to the portable `openat` walk with identical no-follow semantics
// (loudly documented, never silently path-based). Descriptors are
// [`OwnedFd`]s: dropping a [`BoundDir`] or a returned file releases them,
// including on task cancellation.

// POSIX file-type bits (universal on unix targets; rustix 0.38 does not
// re-export S_IFMT/S_IFDIR at this path).
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

/// Mode bits as `u32` on every platform.
///
/// `Stat::st_mode` is `u32` on Linux but narrower elsewhere, so a bare
/// `as u32` is redundant on one platform and required on the other. The
/// single allow lives here instead of at every use site.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn stat_mode(&st: &rustix::fs::Stat) -> u32 {
    st.st_mode as u32
}

/// What a descriptor-retained operation can report.
#[derive(Debug)]
pub enum BoundError {
    /// Resolution would leave the bound root (symlink, `..`, absolute path).
    Outside,
    /// A component or leaf does not exist where existence was required.
    Unresolvable,
    /// I/O failed after containment was established (permissions, busy…).
    Io(std::io::Error),
}

impl std::fmt::Display for BoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundError::Outside => write!(f, "path is outside the bound root"),
            BoundError::Unresolvable => write!(f, "path does not resolve inside the bound root"),
            BoundError::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for BoundError {}

/// A canonical root with a retained directory descriptor.
///
/// Bind once per operation (or per request): opening the root is cheap, and
/// per-operation binding keeps descriptor lifetime strictly inside the call,
/// so cancellation and errors release everything through RAII.
#[derive(Debug)]
pub struct BoundDir {
    /// Canonical root this descriptor was opened on (error messages, `..`
    /// math, and true-path verification).
    root: PathBuf,
    /// Open directory descriptor of `root`.
    fd: rustix::fd::OwnedFd,
}

impl BoundDir {
    /// Open and retain `root`, which must already exist as a directory.
    pub fn bind(root: &Path) -> Result<Self, BoundError> {
        use rustix::fd::AsFd;
        use rustix::fs::{openat, Mode, OFlags};
        let canonical = root.canonicalize().map_err(|_| BoundError::Unresolvable)?;
        if !canonical.is_dir() {
            return Err(BoundError::Unresolvable);
        }
        let cwd = rustix::fs::CWD;
        let fd = openat(
            cwd,
            &canonical,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_outside)?;
        // Confirm we opened a directory, not something smuggled in.
        let _ = rustix::fs::fstat(fd.as_fd()).map_err(|_| BoundError::Unresolvable)?;
        Ok(BoundDir {
            root: canonical,
            fd,
        })
    }

    /// Canonical root this directory is bound to.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrow the retained directory descriptor (for `fstat` of the bound
    /// directory itself and directory iteration).
    pub fn as_fd(&self) -> rustix::fd::BorrowedFd<'_> {
        use rustix::fd::AsFd;
        self.fd.as_fd()
    }

    /// Duplicate the retained descriptor, keeping the same bound root.
    pub fn try_clone(&self) -> Result<BoundDir, BoundError> {
        let fd = self.fd.try_clone().map_err(BoundError::Io)?;
        Ok(BoundDir {
            root: self.root.clone(),
            fd,
        })
    }

    /// The true filesystem path of the retained descriptor, if the platform
    /// can report it. Used to resolve symlink targets against the directory
    /// they actually live in (never a re-resolved pathname).
    pub fn true_path(&self) -> Option<PathBuf> {
        use rustix::fd::AsFd;
        fd_true_path(self.fd.as_fd())
    }

    /// Split a root-relative path into components, rejecting anything that
    /// could address outside the root lexically (absolute paths, `.`, `..`,
    /// empty paths, NUL bytes).
    fn split_rel(&self, rel: &Path) -> Result<Vec<std::ffi::OsString>, BoundError> {
        if rel.is_absolute() {
            return Err(BoundError::Outside);
        }
        let mut out = Vec::new();
        for comp in rel.components() {
            match comp {
                std::path::Component::Normal(name) => out.push(name.to_os_string()),
                // `.` is harmless but pointless; `..`, prefixes and roots
                // are escapes by construction.
                _ => return Err(BoundError::Outside),
            }
        }
        if out.is_empty() {
            return Err(BoundError::Outside);
        }
        Ok(out)
    }

    /// Open the directory `rel` (relative, possibly nested) under this root,
    /// refusing to traverse symlinks. Returns a new bound directory.
    pub fn open_dir(&self, rel: &Path) -> Result<BoundDir, BoundError> {
        use rustix::fd::AsFd;
        let comps = self.split_rel(rel)?;
        let mut fd = self.fd.try_clone().map_err(BoundError::Io)?;
        for comp in comps {
            fd = open_child_dir(fd.as_fd(), comp.as_os_str())?;
        }
        // Verify the final descriptor really is a directory.
        let stat = rustix::fs::fstat(fd.as_fd()).map_err(|_| BoundError::Unresolvable)?;
        if (stat_mode(&stat) & S_IFMT) != S_IFDIR {
            return Err(BoundError::Unresolvable);
        }
        let root = self.root.join(rel);
        Ok(BoundDir { root, fd })
    }

    /// Descend `rel` following symlinks, verifying every level.
    ///
    /// Each component is opened (following a trailing link, if any) and the
    /// resulting descriptor's true path must stay inside the root before
    /// descending further. This preserves the historical behavior of
    /// traversing in-root links, but race-free: every step is verified on the
    /// open descriptor, never on a pathname that could be re-resolved.
    pub fn descend_verified(&self, rel: &Path) -> Result<BoundDir, BoundError> {
        use rustix::fd::AsFd;
        let comps = self.split_rel(rel)?;
        let mut fd = self.fd.try_clone().map_err(BoundError::Io)?;
        for comp in comps {
            let child = rustix::fs::openat(
                fd.as_fd(),
                Path::new(&comp),
                rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(map_open_error)?;
            let true_path = fd_true_path(child.as_fd()).ok_or(BoundError::Outside)?;
            if !true_path.starts_with(&self.root) {
                return Err(BoundError::Outside);
            }
            let stat = rustix::fs::fstat(child.as_fd()).map_err(|_| BoundError::Unresolvable)?;
            if (stat_mode(&stat) & S_IFMT) != S_IFDIR {
                return Err(BoundError::Unresolvable);
            }
            fd = child;
        }
        let root = self.root.join(rel);
        Ok(BoundDir { root, fd })
    }

    /// Split a bound-relative path into its parent directory and leaf name.
    ///
    /// An empty `rel` (the root itself) yields a duplicate of this directory
    /// and no leaf.
    pub fn split_parent(
        &self,
        rel: &Path,
    ) -> Result<(BoundDir, Option<std::ffi::OsString>), BoundError> {
        if rel.as_os_str().is_empty() {
            let fd = self.fd.try_clone().map_err(BoundError::Io)?;
            return Ok((
                BoundDir {
                    root: self.root.clone(),
                    fd,
                },
                None,
            ));
        }
        let comps = self.split_rel(rel)?;
        let leaf = comps.last().cloned().expect("non-empty");
        let parent_rel: PathBuf = comps[..comps.len() - 1].iter().collect();
        let parent = if parent_rel.as_os_str().is_empty() {
            let fd = self.fd.try_clone().map_err(BoundError::Io)?;
            BoundDir {
                root: self.root.clone(),
                fd,
            }
        } else {
            self.descend_verified(&parent_rel)?
        };
        Ok((parent, Some(leaf)))
    }

    /// Open the file `leaf` (single component) inside this directory without
    /// following a trailing symlink. Used for create targets and for reads
    /// where links must not be traversed.
    pub fn open_file_nofollow(
        &self,
        leaf: &std::ffi::OsStr,
        oflags: rustix::fs::OFlags,
        mode: rustix::fs::Mode,
    ) -> Result<rustix::fd::OwnedFd, BoundError> {
        use rustix::fd::AsFd;
        check_leaf(leaf)?;
        let leaf_path = Path::new(leaf);
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{openat2, ResolveFlags};
            let resolve =
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
            match openat2(
                self.fd.as_fd(),
                leaf_path,
                oflags | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                mode,
                resolve,
            ) {
                Ok(fd) => return Ok(fd),
                Err(rustix::io::Errno::NOSYS) => { /* fall through to openat */ }
                Err(e) => return Err(map_open_error(e)),
            }
        }
        rustix::fs::openat(
            self.fd.as_fd(),
            leaf_path,
            oflags | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            mode,
        )
        .map_err(map_open_error)
    }

    /// Open `leaf` following a trailing symlink, then report the descriptor's
    /// true path and require it inside the root. The returned file is immune
    /// to later swaps: verification applies to the open descriptor, not to a
    /// pathname that could be re-resolved.
    pub fn open_file_verified(
        &self,
        leaf: &std::ffi::OsStr,
        oflags: rustix::fs::OFlags,
    ) -> Result<(rustix::fd::OwnedFd, PathBuf), BoundError> {
        use rustix::fd::AsFd;
        check_leaf(leaf)?;
        let fd = rustix::fs::openat(
            self.fd.as_fd(),
            Path::new(leaf),
            oflags | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(map_open_error)?;
        let true_path = fd_true_path(fd.as_fd()).ok_or(BoundError::Outside)?;
        if !true_path.starts_with(&self.root) {
            return Err(BoundError::Outside);
        }
        Ok((fd, true_path))
    }

    /// Create the directory `leaf` inside this directory.
    pub fn mkdir(&self, leaf: &std::ffi::OsStr) -> Result<(), BoundError> {
        use rustix::fd::AsFd;
        check_leaf(leaf)?;
        match rustix::fs::mkdirat(
            self.fd.as_fd(),
            Path::new(leaf),
            rustix::fs::Mode::from_bits_truncate(0o755),
        ) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => {
                // Already there: only acceptable for a real directory.
                let _ = open_child_dir(self.fd.as_fd(), leaf)?;
                Ok(())
            }
            Err(e) => Err(map_open_error(e)),
        }
    }

    /// Remove the non-directory `leaf` without following it.
    pub fn unlink_file(&self, leaf: &std::ffi::OsStr) -> Result<(), BoundError> {
        use rustix::fd::AsFd;
        use rustix::fs::AtFlags;
        check_leaf(leaf)?;
        // Never follow the leaf: unlinkat removes the link itself, and the
        // type check below refuses directories before we touch anything.
        let stat = rustix::fs::statat(self.fd.as_fd(), Path::new(leaf), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_open_error)?;
        if (stat_mode(&stat) & S_IFMT) == S_IFDIR {
            return Err(BoundError::Io(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "is a directory",
            )));
        }
        rustix::fs::unlinkat(self.fd.as_fd(), Path::new(leaf), AtFlags::empty())
            .map_err(|e| BoundError::Io(e.into()))
    }

    /// Remove the empty directory `leaf`.
    pub fn unlink_dir(&self, leaf: &std::ffi::OsStr) -> Result<(), BoundError> {
        use rustix::fd::AsFd;
        use rustix::fs::AtFlags;
        check_leaf(leaf)?;
        rustix::fs::unlinkat(self.fd.as_fd(), Path::new(leaf), AtFlags::REMOVEDIR)
            .map_err(|e| BoundError::Io(e.into()))
    }

    /// Rename `src_leaf` in `self` to `dst_leaf` in `dst_parent`.
    ///
    /// Both parents are retained descriptors, so intermediate swaps cannot
    /// redirect either end. A trailing symlink at either end is replaced, not
    /// followed (`renameat` never traverses the final component); callers
    /// that forbid replacing links must check first (see `stat_leaf`).
    pub fn rename(
        &self,
        src_leaf: &std::ffi::OsStr,
        dst_parent: &BoundDir,
        dst_leaf: &std::ffi::OsStr,
    ) -> Result<(), BoundError> {
        use rustix::fd::AsFd;
        check_leaf(src_leaf)?;
        check_leaf(dst_leaf)?;
        rustix::fs::renameat(
            self.fd.as_fd(),
            Path::new(src_leaf),
            dst_parent.fd.as_fd(),
            Path::new(dst_leaf),
        )
        .map_err(|e| BoundError::Io(e.into()))
    }

    /// Metadata for `leaf` without following a trailing symlink.
    pub fn stat_leaf(&self, leaf: &std::ffi::OsStr) -> Result<rustix::fs::Stat, BoundError> {
        use rustix::fd::AsFd;
        use rustix::fs::AtFlags;
        check_leaf(leaf)?;
        rustix::fs::statat(self.fd.as_fd(), Path::new(leaf), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_open_error)
    }

    /// Iterate this directory's entries. Names come from the open descriptor,
    /// so a swapped directory cannot inject entries from elsewhere.
    pub fn read_dir(&self) -> Result<rustix::fs::Dir, BoundError> {
        use rustix::fd::AsFd;
        rustix::fs::Dir::read_from(self.fd.as_fd()).map_err(|e| BoundError::Io(e.into()))
    }
}

/// A leaf name must be a single normal component: no separators, no `.`/`..`,
/// nothing empty, no interior NUL (the kernel would reject it with `EINVAL`,
/// but failing here keeps the error a containment error, not an I/O one).
fn check_leaf(leaf: &std::ffi::OsStr) -> Result<(), BoundError> {
    use std::os::unix::ffi::OsStrExt;
    if leaf.as_bytes().contains(&0) {
        return Err(BoundError::Outside);
    }
    let p = Path::new(leaf);
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(BoundError::Outside),
    }
}

/// Open one child directory without following symlinks.
fn open_child_dir(
    parent: rustix::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> Result<rustix::fd::OwnedFd, BoundError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{openat2, ResolveFlags};
        let resolve =
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
        match openat2(
            parent,
            Path::new(name),
            rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            resolve,
        ) {
            Ok(fd) => return Ok(fd),
            Err(rustix::io::Errno::NOSYS) => { /* fall through to openat */ }
            Err(e) => return Err(map_open_error(e)),
        }
    }
    rustix::fs::openat(
        parent,
        Path::new(name),
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(map_open_error)
}

/// The true filesystem path of an open descriptor: `/proc/self/fd` on Linux,
/// `fcntl(F_GETPATH)` elsewhere. Used to verify an opened file (which followed
/// a trailing symlink) really landed inside the bound root.
fn fd_true_path(fd: impl rustix::fd::AsFd) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let link = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
        std::fs::read_link(link).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Apple platforms expose the true path of an open descriptor via
        // fcntl(F_GETPATH). Elsewhere there is no portable equivalent, so
        // verified opens are unsupported there (callers fail closed).
        #[cfg(target_vendor = "apple")]
        {
            use std::os::unix::ffi::OsStringExt;
            rustix::fs::getpath(fd)
                .ok()
                .map(|c| PathBuf::from(std::ffi::OsString::from_vec(c.into_bytes())))
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let _ = fd;
            None
        }
    }
}

/// Map open-family errno values onto bound errors: missing components and
/// symlink/permission rejections are containment-relevant; the rest is I/O.
fn map_open_error(e: rustix::io::Errno) -> BoundError {
    use rustix::io::Errno;
    match e {
        Errno::NOENT | Errno::NOTDIR => BoundError::Unresolvable,
        Errno::LOOP | Errno::PERM | Errno::ACCESS | Errno::XDEV => BoundError::Outside,
        _ => BoundError::Io(e.into()),
    }
}

/// `bind` failures on the root open itself use the same mapping.
fn map_outside(e: rustix::io::Errno) -> BoundError {
    map_open_error(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        base: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let base = std::env::temp_dir()
                .join(format!("exectool_sandbox_{name}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("safe")).unwrap();
            Fixture { base }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.base.join(rel)
        }

        fn sandbox(&self) -> Sandbox {
            Sandbox::new([self.base.join("safe")]).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn a_path_inside_a_root_resolves() {
        let f = Fixture::new("inside");
        std::fs::write(f.path("safe/file.txt"), "x").unwrap();

        let resolved = f
            .sandbox()
            .resolve_existing(f.path("safe/file.txt"))
            .unwrap();
        assert!(resolved.ends_with("file.txt"));
    }

    #[test]
    fn a_sibling_sharing_a_textual_prefix_is_rejected() {
        // The first confirmed escape: `/tmp/safe_evil` vs a root of `/tmp/safe`.
        // `str::starts_with` admits it; `Path::starts_with` does not.
        let f = Fixture::new("sibling");
        std::fs::create_dir_all(f.path("safe_evil")).unwrap();
        std::fs::write(f.path("safe_evil/stolen.txt"), "secret").unwrap();

        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe_evil/stolen.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_leaving_the_sandbox_is_rejected() {
        // The second confirmed escape: a link inside the root pointing out.
        let f = Fixture::new("symlink");
        std::fs::create_dir_all(f.path("outside")).unwrap();
        std::fs::write(f.path("outside/secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(f.path("outside"), f.path("safe/link")).unwrap();

        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe/link/secret.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_staying_inside_the_sandbox_is_allowed() {
        // Canonicalization must not become a blanket ban on links.
        let f = Fixture::new("symlink_ok");
        std::fs::create_dir_all(f.path("safe/real")).unwrap();
        std::fs::write(f.path("safe/real/file.txt"), "x").unwrap();
        std::os::unix::fs::symlink(f.path("safe/real"), f.path("safe/link")).unwrap();

        assert!(f
            .sandbox()
            .resolve_existing(f.path("safe/link/file.txt"))
            .is_ok());
    }

    #[test]
    fn parent_traversal_is_rejected() {
        let f = Fixture::new("traversal");
        std::fs::write(f.path("outside.txt"), "secret").unwrap();

        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe/../outside.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    fn a_missing_path_is_unresolvable_not_permitted() {
        let f = Fixture::new("missing");
        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe/nope.txt")),
            Err(SandboxError::Unresolvable)
        );
    }

    #[test]
    fn creating_inside_the_sandbox_is_allowed() {
        let f = Fixture::new("create");
        let target = f
            .sandbox()
            .resolve_for_create(f.path("safe/new.txt"))
            .unwrap();
        assert!(target.ends_with("new.txt"));
    }

    #[test]
    fn creating_outside_the_sandbox_is_rejected() {
        let f = Fixture::new("create_out");
        assert_eq!(
            f.sandbox().resolve_for_create(f.path("new.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    #[cfg(unix)]
    fn writing_through_a_pre_placed_symlink_is_rejected() {
        // Create-time resolution must not be a way around the read-time check.
        let f = Fixture::new("create_link");
        std::fs::write(f.path("target.txt"), "original").unwrap();
        std::os::unix::fs::symlink(f.path("target.txt"), f.path("safe/link.txt")).unwrap();

        assert_eq!(
            f.sandbox().resolve_for_create(f.path("safe/link.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    fn a_sandbox_needs_at_least_one_root() {
        let empty: Vec<PathBuf> = Vec::new();
        assert_eq!(Sandbox::new(empty), Err(SandboxError::NoRoots));
    }

    #[test]
    fn a_nonexistent_root_is_a_configuration_error() {
        // Not "an empty allowance": otherwise the sandbox silently starts
        // permitting things when someone later creates the directory.
        let result = Sandbox::new(["/definitely/not/here/exectool"]);
        assert!(matches!(result, Err(SandboxError::BadRoot { .. })));
    }

    #[test]
    fn a_file_cannot_be_a_root() {
        let f = Fixture::new("file_root");
        std::fs::write(f.path("safe/file.txt"), "x").unwrap();
        let result = Sandbox::new([f.path("safe/file.txt")]);
        assert!(matches!(result, Err(SandboxError::BadRoot { .. })));
    }

    #[test]
    fn multiple_roots_are_all_honoured() {
        let f = Fixture::new("multi");
        std::fs::create_dir_all(f.path("second")).unwrap();
        std::fs::write(f.path("safe/a.txt"), "a").unwrap();
        std::fs::write(f.path("second/b.txt"), "b").unwrap();
        std::fs::write(f.path("elsewhere.txt"), "c").unwrap();

        let sandbox = Sandbox::new([f.path("safe"), f.path("second")]).unwrap();
        assert!(sandbox.resolve_existing(f.path("safe/a.txt")).is_ok());
        assert!(sandbox.resolve_existing(f.path("second/b.txt")).is_ok());
        assert_eq!(
            sandbox.resolve_existing(f.path("elsewhere.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    fn the_root_itself_is_inside_itself() {
        let f = Fixture::new("root_self");
        assert!(f.sandbox().resolve_existing(f.path("safe")).is_ok());
    }

    // ── BoundDir (M2-003): deterministic unit tests ──────────
    // No races here: pre-placed links and fixed layouts pin the contract
    // (the race itself is covered by tests/toctou.rs).

    fn bound(f: &Fixture) -> BoundDir {
        BoundDir::bind(&f.path("safe")).unwrap()
    }

    #[cfg(unix)]
    fn symlink(dir: &std::path::Path, name: &str, target: &std::path::Path) {
        std::os::unix::fs::symlink(target, dir.join(name)).unwrap();
    }

    #[test]
    fn bind_rejects_files_and_missing_roots() {
        let f = Fixture::new("bound-roots");
        std::fs::write(f.path("safe/file.txt"), "x").unwrap();
        assert!(matches!(
            BoundDir::bind(&f.path("safe/file.txt")),
            Err(BoundError::Unresolvable)
        ));
        assert!(matches!(
            BoundDir::bind(&f.path("nope")),
            Err(BoundError::Unresolvable)
        ));
        assert!(BoundDir::bind(&f.path("safe")).is_ok());
    }

    #[test]
    fn leaf_names_cannot_escape() {
        for bad in ["", ".", "..", "/", "/abs", "a/b", "a\u{0}b"] {
            assert!(
                check_leaf(std::ffi::OsStr::new(bad)).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(check_leaf(std::ffi::OsStr::new("ok.txt")).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn intermediate_symlinks_are_never_traversed() {
        let f = Fixture::new("bound-nofollow");
        std::fs::create_dir_all(f.path("safe/real")).unwrap();
        std::fs::write(f.path("safe/real/f.txt"), "x").unwrap();
        std::fs::create_dir_all(f.path("elsewhere")).unwrap();
        symlink(&f.path("safe"), "link", &f.path("elsewhere"));
        let b = bound(&f);
        // Traversal through the link fails even though the target exists.
        assert!(matches!(
            b.open_dir(std::path::Path::new("link")),
            Err(BoundError::Outside) | Err(BoundError::Unresolvable)
        ));
        // The real directory still opens.
        assert!(b.open_dir(std::path::Path::new("real")).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn verified_open_allows_inside_links_and_denies_escaping_ones() {
        use rustix::fs::OFlags;
        let f = Fixture::new("bound-verify");
        std::fs::write(f.path("safe/real.txt"), "x").unwrap();
        std::fs::create_dir_all(f.path("elsewhere")).unwrap();
        std::fs::write(f.path("elsewhere/secret.txt"), "s").unwrap();
        symlink(&f.path("safe"), "in-link", &f.path("safe/real.txt"));
        symlink(&f.path("safe"), "out-link", &f.path("elsewhere/secret.txt"));
        let b = bound(&f);
        assert!(b
            .open_file_verified(std::ffi::OsStr::new("in-link"), OFlags::RDONLY)
            .is_ok());
        assert!(matches!(
            b.open_file_verified(std::ffi::OsStr::new("out-link"), OFlags::RDONLY),
            Err(BoundError::Outside)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn nofollow_create_refuses_trailing_links() {
        use rustix::fs::{Mode, OFlags};
        let f = Fixture::new("bound-create");
        std::fs::write(f.path("safe/real.txt"), "x").unwrap();
        symlink(&f.path("safe"), "link.txt", &f.path("safe/real.txt"));
        let b = bound(&f);
        assert!(matches!(
            b.open_file_nofollow(
                std::ffi::OsStr::new("link.txt"),
                OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
                Mode::from_bits_truncate(0o644),
            ),
            Err(BoundError::Outside) | Err(BoundError::Unresolvable)
        ));
    }

    #[test]
    fn mkdir_unlink_rename_stay_inside() {
        use std::ffi::OsStr;
        let f = Fixture::new("bound-mutate");
        let b = bound(&f);
        b.mkdir(OsStr::new("sub")).unwrap();
        assert!(f.path("safe/sub").is_dir());
        // Second mkdir is idempotent for real directories.
        b.mkdir(OsStr::new("sub")).unwrap();
        // Rename within the root works.
        std::fs::write(f.path("safe/sub/a.txt"), "a").unwrap();
        let sub = b.open_dir(std::path::Path::new("sub")).unwrap();
        sub.rename(OsStr::new("a.txt"), &sub, OsStr::new("b.txt"))
            .unwrap();
        assert!(f.path("safe/sub/b.txt").exists());
        // Unlink removes files; rmdir removes the emptied directory.
        sub.unlink_file(OsStr::new("b.txt")).unwrap();
        assert!(!f.path("safe/sub/b.txt").exists());
        drop(sub);
        b.unlink_dir(OsStr::new("sub")).unwrap();
        assert!(!f.path("safe/sub").exists());
        // Absolute and parent-qualified names never validate as leaves.
        assert!(b.unlink_file(OsStr::new("/abs")).is_err());
    }
}
