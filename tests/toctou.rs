//! Adversarial filesystem containment tests (M2-003).
//!
//! A symlink or directory swapped *between* authorization and I/O must not
//! redirect a mutation outside the authorized root. The swap-race tests run a
//! racer thread hot-swapping a symlink while the test task performs the
//! operation in a loop: pre-fix runs demonstrate outside-root mutation (the
//! evidence is recorded in docs/engineering/m2-003-filesystem-safety.md);
//! post-fix runs must show zero outside mutations across the same shape.
//! All fixtures live under the system temp dir and are removed on drop.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use marshall::{FileSystemTool, Sandbox, Tool};
use serde_json::json;

struct Fixture {
    base: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "marshall_toctou_{name}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("root")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        Fixture { base }
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.base.join(rel)
    }

    fn tool(&self) -> FileSystemTool {
        FileSystemTool::new(Sandbox::new([self.at("root")]).unwrap()).writable()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Alternate the directory at `path` between a real directory and a symlink
/// to `link_target`, until `done` is set.
///
/// A plain atomic rename cannot replace a non-empty directory with a symlink
/// (POSIX forbids it), so the cycle is remove-and-recreate: brief moments
/// exist where `path` is missing (victim ops then fail closed) and where it
/// is a link (victim checks then deny). The dangerous alignment is a victim
/// that authorizes while `path` is real and performs I/O after it became a
/// link — exactly the check-to-use race under test.
#[cfg(unix)]
fn spawn_dir_swapper(
    path: PathBuf,
    link_target: PathBuf,
    done: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let staging = path.with_extension("stage");
        while !done.load(Ordering::Relaxed) {
            // real dir -> symlink to link_target
            let _ = std::fs::rename(&path, &staging);
            let _ = std::os::unix::fs::symlink(&link_target, &path);
            std::thread::sleep(std::time::Duration::from_micros(80));
            // symlink -> real dir
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::rename(&staging, &path);
            std::thread::sleep(std::time::Duration::from_micros(80));
        }
        // Leave the fixture as a real directory.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::rename(&staging, &path);
    })
}

const ITERATIONS: usize = 1500;

/// Write through a swapped *intermediate directory* must never land outside
/// the root.
///
/// Swapping the leaf link is always re-resolved before use, so the race that
/// matters replaces `root/sub` itself: a real directory alternating with a
/// symlink to `outside/`. A write admitted while `sub` is real must not land
/// in `outside/` if the swap lands between authorization and I/O.
#[tokio::test]
#[cfg(unix)]
async fn swap_race_write_never_escapes_root() {
    let f = Fixture::new("write");
    std::fs::create_dir_all(f.at("root/sub-real")).unwrap();
    std::fs::write(f.at("root/sub-real/file.txt"), "real").unwrap();
    std::fs::create_dir_all(f.at("outside")).unwrap();

    // The race must swap a component of the *canonical* path: resolved
    // paths contain no symlinks, so aliasing `sub` cannot redirect I/O.
    // `root/sub-real` itself alternates between a real directory and a link
    // to `outside/`.
    std::fs::create_dir_all(f.at("root/sub-real")).unwrap();
    std::fs::write(f.at("root/sub-real/file.txt"), "real").unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let racer = spawn_dir_swapper(f.at("root/sub-real"), f.at("outside"), done.clone());

    let tool = f.tool();
    for i in 0..ITERATIONS {
        // Admitted-while-real iterations must still land inside; iterations
        // that observe the link fail closed. Either way `outside/file.txt`
        // must never gain our payload.
        let _ = tool
            .execute(json!({
                "operation": "write",
                "path": f.at("root/sub-real/file.txt").to_string_lossy(),
                "content": format!("PAYLOAD-{i}"),
            }))
            .await;
    }
    done.store(true, Ordering::Relaxed);
    racer.join().unwrap();

    let escaped = f.at("outside/file.txt");
    assert!(
        !escaped.exists()
            || !std::fs::read_to_string(&escaped)
                .unwrap()
                .contains("PAYLOAD"),
        "write escaped the root through a swapped directory"
    );
}

/// Same race under a session scope: the session-external directory (still
/// inside the workspace sandbox) must never receive the payload.
#[tokio::test]
#[cfg(unix)]
async fn swap_race_write_never_escapes_session() {
    let f = Fixture::new("write-session");
    std::fs::create_dir_all(f.at("root/session")).unwrap();
    std::fs::create_dir_all(f.at("root/shared")).unwrap();
    let scope = f
        .at("root/session")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    std::fs::create_dir_all(f.at("root/session/sub-real")).unwrap();
    std::fs::write(f.at("root/session/sub-real/file.txt"), "real").unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let racer = spawn_dir_swapper(
        f.at("root/session/sub-real"),
        f.at("root/shared"),
        done.clone(),
    );

    let tool = f.tool();
    for i in 0..ITERATIONS {
        let _ = tool
            .execute(json!({
                "operation": "write",
                "path": f.at("root/session/sub-real/file.txt").to_string_lossy(),
                "content": format!("PAYLOAD-{i}"),
                marshall::server::SESSION_SCOPE_KEY: scope,
            }))
            .await;
    }
    done.store(true, Ordering::Relaxed);
    racer.join().unwrap();

    let escaped = f.at("root/shared/file.txt");
    assert!(
        !escaped.exists()
            || !std::fs::read_to_string(&escaped)
                .unwrap()
                .contains("PAYLOAD"),
        "write escaped the session through a swapped directory"
    );
}

/// Append through a swapped intermediate directory must never land outside
/// the root (same race shape as write; append additionally reads first).
#[tokio::test]
#[cfg(unix)]
async fn swap_race_append_never_escapes_root() {
    let f = Fixture::new("append");
    std::fs::write(f.at("root/real.txt"), "real").unwrap();
    std::fs::create_dir_all(f.at("outside")).unwrap();
    std::fs::write(f.at("outside/secret.txt"), "SECRET").unwrap();
    std::fs::create_dir_all(f.at("root/sub-real")).unwrap();
    std::fs::write(f.at("root/sub-real/file.txt"), "real").unwrap();

    let done = Arc::new(AtomicBool::new(false));
    let racer = spawn_dir_swapper(f.at("root/sub-real"), f.at("outside"), done.clone());

    let tool = f.tool();
    for i in 0..500 {
        let _ = tool
            .execute(json!({
                "operation": "append",
                "path": f.at("root/sub-real/file.txt").to_string_lossy(),
                "content": format!("-{i}"),
            }))
            .await;
    }
    done.store(true, Ordering::Relaxed);
    racer.join().unwrap();

    let escaped = f.at("outside/file.txt");
    assert!(
        !escaped.exists() || !std::fs::read_to_string(&escaped).unwrap().contains("-0"),
        "append escaped the root through a swapped directory"
    );
}

/// Concurrent scoped requests cannot bypass containment.
#[tokio::test]
async fn concurrent_scoped_writes_stay_inside() {
    let f = Fixture::new("concurrent");
    std::fs::create_dir_all(f.at("root/a")).unwrap();
    std::fs::create_dir_all(f.at("root/b")).unwrap();
    let scope_a = f
        .at("root/a")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let tool = Arc::new(f.tool());

    let mut handles = Vec::new();
    for i in 0..16usize {
        let tool = tool.clone();
        let (scope, rel) = if i % 2 == 0 {
            (scope_a.clone(), format!("root/a/f{i}.txt"))
        } else {
            // No scope: workspace behavior confines to the sandbox root.
            (String::new(), format!("root/b/f{i}.txt"))
        };
        let path = f.at(&rel).to_string_lossy().into_owned();
        handles.push(tokio::spawn(async move {
            let mut args = serde_json::json!({
                "operation": "write",
                "path": path,
                "content": "x",
            });
            if !scope.is_empty() {
                args[marshall::server::SESSION_SCOPE_KEY] = json!(scope);
            }
            tool.execute(args).await.map(|o| o.success).unwrap_or(false)
        }));
    }
    for h in handles {
        assert!(h.await.unwrap());
    }
    assert_eq!(std::fs::read_dir(f.at("root/a")).unwrap().count(), 8);
    assert_eq!(std::fs::read_dir(f.at("root/b")).unwrap().count(), 8);
}

/// Repeated failures and cancellation must not leak file descriptors.
#[tokio::test]
#[cfg(target_os = "linux")]
async fn fd_count_is_stable_across_failures() {
    fn fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|d| d.count())
            .unwrap_or(0)
    }
    let f = Fixture::new("fds");
    let tool = f.tool();
    let before = fd_count();
    for _ in 0..200 {
        let _ = tool
            .execute(
                json!({"operation": "read", "path": f.at("root/missing.txt").to_string_lossy()}),
            )
            .await;
        let _ = tool
            .execute(json!({"operation": "read", "path": "/definitely/outside.txt"}))
            .await;
    }
    // Cancel a batch of slow operations mid-flight, then measure.
    let slow = async {
        for _ in 0..50 {
            let _ = tool
                .execute(json!({"operation": "read", "path": f.at("root/missing.txt").to_string_lossy()}))
                .await;
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        _ = slow => {},
        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {},
    }
    tokio::task::yield_now().await;
    let after = fd_count();
    assert!(after <= before + 8, "fd leak: {before} -> {after}");
}
