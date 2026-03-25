//! Filesystem change tracking via block device or overlay diffs.
//!
//! Two strategies are supported:
//!
//! 1. **OverlayFS upper-dir scanning** — walks the overlay upper directory to
//!    find files created, modified, or deleted (whiteout entries). This is the
//!    preferred approach when the provider exposes overlay mounts (Firecracker
//!    with overlayfs rootfs).
//!
//! 2. **Snapshot diffing** — compares two directory trees representing the
//!    filesystem before and after agent execution. Used for providers that
//!    expose block-device snapshots (virtio-blk) or devcontainer filesystems
//!    (Daytona, generic).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{CapturedEvent, EventType};

/// Configuration for filesystem change tracking.
#[derive(Debug, Clone)]
pub struct FsTrackingConfig {
    /// Agent identifier for event attribution.
    pub agent_id: String,
    /// Trace identifier for this capture session.
    pub trace_id: String,
    /// Which tracking method to use.
    pub method: FsTrackingMethod,
}

/// The strategy used to detect filesystem changes.
#[derive(Debug, Clone)]
pub enum FsTrackingMethod {
    /// Scan the OverlayFS upper directory for changes.
    /// The path points to the overlay upper dir (e.g., `/overlay/upper`).
    OverlayUpperDir { upper_dir: PathBuf },

    /// Diff two directory trees representing before/after snapshots.
    /// Used when the provider mounts block-device snapshots.
    SnapshotDiff {
        before: PathBuf,
        after: PathBuf,
    },
}

/// Per-file change detail including size.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileDetail {
    pub path: String,
    pub size_bytes: u64,
}

/// Structured representation of a filesystem change summary.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FsSummary {
    pub files_created: Vec<String>,
    pub files_modified: Vec<String>,
    pub files_deleted: Vec<String>,
    pub total_bytes_written: u64,
    /// Per-file size details (path → size in bytes).
    /// Deleted files have size 0.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub file_sizes: BTreeMap<String, u64>,
}

impl FsSummary {
    pub fn to_event(&self, agent_id: &str, trace_id: &str) -> CapturedEvent {
        CapturedEvent::new(
            EventType::FilesystemSummary,
            agent_id,
            trace_id,
            serde_json::to_value(self).expect("FsSummary is always serializable"),
        )
    }
}

/// Capture filesystem changes using the configured method.
pub fn capture_fs_changes(config: &FsTrackingConfig) -> Result<Vec<CapturedEvent>> {
    let summary = match &config.method {
        FsTrackingMethod::OverlayUpperDir { upper_dir } => {
            scan_overlay_upper(upper_dir)
                .with_context(|| format!("overlay scan of {}", upper_dir.display()))?
        }
        FsTrackingMethod::SnapshotDiff { before, after } => {
            diff_snapshots(before, after)
                .with_context(|| format!(
                    "snapshot diff {} vs {}",
                    before.display(),
                    after.display()
                ))?
        }
    };

    if summary.files_created.is_empty()
        && summary.files_modified.is_empty()
        && summary.files_deleted.is_empty()
    {
        tracing::debug!("no filesystem changes detected");
        return Ok(vec![]);
    }

    tracing::info!(
        created = summary.files_created.len(),
        modified = summary.files_modified.len(),
        deleted = summary.files_deleted.len(),
        bytes = summary.total_bytes_written,
        "filesystem changes captured"
    );

    Ok(vec![summary.to_event(&config.agent_id, &config.trace_id)])
}

// ---------------------------------------------------------------------------
// OverlayFS upper-dir scanning
// ---------------------------------------------------------------------------

/// Scan an OverlayFS upper directory to detect filesystem changes.
///
/// OverlayFS semantics:
/// - Regular files/dirs in the upper dir → created or modified
/// - Character device with rdev 0 (major 0, minor 0) → whiteout (deleted)
/// - Directories with `trusted.overlay.opaque` xattr → opaque (replaced entirely)
///
/// Since we cannot distinguish "created" from "modified" using only the upper
/// dir (both appear as regular files), we classify non-whiteout entries as
/// "modified" and whiteout entries as "deleted". Callers can cross-reference
/// with a known base image manifest to reclassify modified → created.
fn scan_overlay_upper(upper_dir: &Path) -> Result<FsSummary> {
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    let mut file_sizes = BTreeMap::new();
    let mut total_bytes: u64 = 0;

    walk_overlay_dir(upper_dir, upper_dir, &mut modified, &mut deleted, &mut file_sizes, &mut total_bytes)?;

    Ok(FsSummary {
        files_created: Vec::new(), // cannot distinguish from modified via upper-dir alone
        files_modified: modified,
        files_deleted: deleted,
        total_bytes_written: total_bytes,
        file_sizes,
    })
}

fn walk_overlay_dir(
    root: &Path,
    dir: &Path,
    modified: &mut Vec<String>,
    deleted: &mut Vec<String>,
    file_sizes: &mut BTreeMap<String, u64>,
    total_bytes: &mut u64,
) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        // Use symlink_metadata (lstat) to avoid following symlinks.
        // A malicious agent could plant symlinks pointing to sensitive host
        // files; following them would leak metadata or content.
        let metadata = fs::symlink_metadata(entry.path())?;

        if metadata.file_type().is_symlink() {
            tracing::warn!(
                path = %entry.path().display(),
                "skipping symlink in overlay upper dir (potential host escape)"
            );
            continue;
        }

        let rel = entry.path()
            .strip_prefix(root)
            .unwrap_or(entry.path().as_path())
            .to_string_lossy()
            .to_string();
        let rel_path = format!("/{rel}");

        if is_whiteout(&metadata) {
            deleted.push(rel_path.clone());
            file_sizes.insert(rel_path, 0);
        } else if metadata.is_dir() {
            walk_overlay_dir(root, &entry.path(), modified, deleted, file_sizes, total_bytes)?;
        } else {
            let size = metadata.len();
            modified.push(rel_path.clone());
            file_sizes.insert(rel_path, size);
            *total_bytes = total_bytes.saturating_add(size);
        }
    }

    Ok(())
}

/// Check if a file is an overlayfs whiteout (character device 0,0).
fn is_whiteout(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_char_device() && metadata.rdev() == 0
}

// ---------------------------------------------------------------------------
// Snapshot diffing
// ---------------------------------------------------------------------------

/// File entry collected during a directory walk.
#[derive(Debug)]
struct FileEntry {
    size: u64,
    mtime_ns: i64,
    is_dir: bool,
}

/// Diff two directory trees (before and after snapshots) to find changes.
///
/// Classification:
/// - Present in `after` but not `before` → created
/// - Present in both but size or mtime changed → modified
/// - Present in `before` but not `after` → deleted
fn diff_snapshots(before: &Path, after: &Path) -> Result<FsSummary> {
    let before_map = walk_tree(before)
        .with_context(|| format!("walking before snapshot {}", before.display()))?;
    let after_map = walk_tree(after)
        .with_context(|| format!("walking after snapshot {}", after.display()))?;

    let mut created = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    let mut file_sizes = BTreeMap::new();
    let mut total_bytes: u64 = 0;

    // Files in after but not in before → created.
    // Files in both but changed → modified.
    for (path, after_entry) in &after_map {
        if after_entry.is_dir {
            continue;
        }
        match before_map.get(path) {
            None => {
                created.push(path.clone());
                file_sizes.insert(path.clone(), after_entry.size);
                total_bytes = total_bytes.saturating_add(after_entry.size);
            }
            Some(before_entry) => {
                if before_entry.size != after_entry.size
                    || before_entry.mtime_ns != after_entry.mtime_ns
                {
                    modified.push(path.clone());
                    file_sizes.insert(path.clone(), after_entry.size);
                    total_bytes = total_bytes.saturating_add(after_entry.size);
                }
            }
        }
    }

    // Files in before but not in after → deleted.
    for (path, entry) in &before_map {
        if entry.is_dir {
            continue;
        }
        if !after_map.contains_key(path) {
            deleted.push(path.clone());
            file_sizes.insert(path.clone(), 0);
        }
    }

    // Sort for deterministic output.
    created.sort();
    modified.sort();
    deleted.sort();

    Ok(FsSummary {
        files_created: created,
        files_modified: modified,
        files_deleted: deleted,
        total_bytes_written: total_bytes,
        file_sizes,
    })
}

/// Recursively walk a directory tree, collecting file metadata keyed by
/// relative path (prefixed with `/`).
fn walk_tree(root: &Path) -> Result<BTreeMap<String, FileEntry>> {
    let mut map = BTreeMap::new();
    walk_tree_inner(root, root, &mut map)?;
    Ok(map)
}

fn walk_tree_inner(
    root: &Path,
    dir: &Path,
    map: &mut BTreeMap<String, FileEntry>,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::warn!(path = %dir.display(), "permission denied, skipping");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        // Use symlink_metadata (lstat) to avoid following symlinks.
        // A malicious agent could plant symlinks pointing to sensitive host
        // files; following them would leak metadata or content.
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::warn!(path = %entry.path().display(), "permission denied, skipping");
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        if metadata.file_type().is_symlink() {
            tracing::warn!(
                path = %entry.path().display(),
                "skipping symlink in snapshot tree (potential host escape)"
            );
            continue;
        }

        let rel = entry.path()
            .strip_prefix(root)
            .unwrap_or(entry.path().as_path())
            .to_string_lossy()
            .to_string();
        let rel_path = format!("/{rel}");

        let fe = FileEntry {
            size: metadata.len(),
            mtime_ns: metadata.mtime_nsec(),
            is_dir: metadata.is_dir(),
        };

        map.insert(rel_path, fe);

        if metadata.is_dir() {
            walk_tree_inner(root, &entry.path(), map)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_snapshot_diff_created() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();

        // Create a file only in "after"
        fs::write(after.path().join("new.txt"), "hello").unwrap();

        let summary = diff_snapshots(before.path(), after.path()).unwrap();
        assert_eq!(summary.files_created, vec!["/new.txt"]);
        assert!(summary.files_modified.is_empty());
        assert!(summary.files_deleted.is_empty());
        assert_eq!(summary.total_bytes_written, 5);
        assert_eq!(summary.file_sizes["/new.txt"], 5);
    }

    #[test]
    fn test_snapshot_diff_deleted() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();

        // Create a file only in "before"
        fs::write(before.path().join("gone.txt"), "bye").unwrap();

        let summary = diff_snapshots(before.path(), after.path()).unwrap();
        assert!(summary.files_created.is_empty());
        assert!(summary.files_modified.is_empty());
        assert_eq!(summary.files_deleted, vec!["/gone.txt"]);
        assert_eq!(summary.total_bytes_written, 0);
        assert_eq!(summary.file_sizes["/gone.txt"], 0);
    }

    #[test]
    fn test_snapshot_diff_modified() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();

        // Same filename, different content (different size)
        fs::write(before.path().join("data.bin"), "short").unwrap();
        fs::write(after.path().join("data.bin"), "much longer content").unwrap();

        let summary = diff_snapshots(before.path(), after.path()).unwrap();
        assert!(summary.files_created.is_empty());
        assert_eq!(summary.files_modified, vec!["/data.bin"]);
        assert!(summary.files_deleted.is_empty());
        assert_eq!(summary.total_bytes_written, 19);
    }

    #[test]
    fn test_snapshot_diff_mixed() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();

        // Before: a.txt, b.txt
        fs::write(before.path().join("a.txt"), "aaa").unwrap();
        fs::write(before.path().join("b.txt"), "bbb").unwrap();

        // After: a.txt (modified), c.txt (created), b.txt deleted
        fs::write(after.path().join("a.txt"), "aaa-modified").unwrap();
        fs::write(after.path().join("c.txt"), "new").unwrap();

        let summary = diff_snapshots(before.path(), after.path()).unwrap();
        assert_eq!(summary.files_created, vec!["/c.txt"]);
        assert_eq!(summary.files_modified, vec!["/a.txt"]);
        assert_eq!(summary.files_deleted, vec!["/b.txt"]);
    }

    #[test]
    fn test_snapshot_diff_nested_dirs() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();

        // Create nested structure in after
        fs::create_dir_all(after.path().join("src/lib")).unwrap();
        fs::write(after.path().join("src/lib/main.rs"), "fn main() {}").unwrap();
        fs::write(after.path().join("src/util.rs"), "// util").unwrap();

        let summary = diff_snapshots(before.path(), after.path()).unwrap();
        assert_eq!(summary.files_created.len(), 2);
        assert!(summary.files_created.contains(&"/src/lib/main.rs".to_string()));
        assert!(summary.files_created.contains(&"/src/util.rs".to_string()));
    }

    #[test]
    fn test_overlay_upper_scan() {
        let upper = tempfile::tempdir().unwrap();

        // Regular files in upper dir = modified/created
        fs::write(upper.path().join("changed.txt"), "new content").unwrap();
        fs::create_dir_all(upper.path().join("subdir")).unwrap();
        fs::write(upper.path().join("subdir/nested.txt"), "nested").unwrap();

        let summary = scan_overlay_upper(upper.path()).unwrap();
        // Overlay scan classifies everything as modified (can't distinguish created)
        assert!(summary.files_created.is_empty());
        assert_eq!(summary.files_modified.len(), 2);
        assert!(summary.files_modified.contains(&"/changed.txt".to_string()));
        assert!(summary.files_modified.contains(&"/subdir/nested.txt".to_string()));
        assert_eq!(summary.total_bytes_written, 11 + 6); // "new content" + "nested"
    }

    #[test]
    fn test_empty_changes_produce_no_events() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();

        let config = FsTrackingConfig {
            agent_id: "test-agent".to_string(),
            trace_id: "test-trace".to_string(),
            method: FsTrackingMethod::SnapshotDiff {
                before: before.path().to_path_buf(),
                after: after.path().to_path_buf(),
            },
        };

        let events = capture_fs_changes(&config).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_capture_produces_event() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();
        fs::write(after.path().join("file.txt"), "data").unwrap();

        let config = FsTrackingConfig {
            agent_id: "agent-1".to_string(),
            trace_id: "trace-1".to_string(),
            method: FsTrackingMethod::SnapshotDiff {
                before: before.path().to_path_buf(),
                after: after.path().to_path_buf(),
            },
        };

        let events = capture_fs_changes(&config).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, crate::EventType::FilesystemSummary);
        assert_eq!(events[0].agent_id, "agent-1");
        assert_eq!(events[0].trace_id, "trace-1");

        let summary: FsSummary = serde_json::from_value(events[0].payload.clone()).unwrap();
        assert_eq!(summary.files_created, vec!["/file.txt"]);
        assert_eq!(summary.total_bytes_written, 4);
    }

    #[test]
    fn test_snapshot_diff_skips_symlinks() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();

        // Create a regular file and a symlink in "after"
        fs::write(after.path().join("real.txt"), "real").unwrap();
        std::os::unix::fs::symlink("/etc/shadow", after.path().join("evil_link")).unwrap();

        let summary = diff_snapshots(before.path(), after.path()).unwrap();
        // Only the real file should appear, symlink must be skipped
        assert_eq!(summary.files_created, vec!["/real.txt"]);
        assert!(!summary.files_created.contains(&"/evil_link".to_string()));
        assert!(summary.files_modified.is_empty());
        assert!(summary.files_deleted.is_empty());
    }

    #[test]
    fn test_overlay_scan_skips_symlinks() {
        let upper = tempfile::tempdir().unwrap();

        // Regular file + symlink in upper dir
        fs::write(upper.path().join("legit.txt"), "ok").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", upper.path().join("sneaky")).unwrap();

        let summary = scan_overlay_upper(upper.path()).unwrap();
        // Only legit.txt should appear
        assert_eq!(summary.files_modified.len(), 1);
        assert!(summary.files_modified.contains(&"/legit.txt".to_string()));
        assert!(!summary.files_modified.contains(&"/sneaky".to_string()));
    }

    #[test]
    fn test_fs_summary_serialization_roundtrip() {
        let summary = FsSummary {
            files_created: vec!["/a.txt".to_string()],
            files_modified: vec!["/b.txt".to_string()],
            files_deleted: vec!["/c.txt".to_string()],
            total_bytes_written: 42,
            file_sizes: BTreeMap::from([
                ("/a.txt".to_string(), 10),
                ("/b.txt".to_string(), 32),
                ("/c.txt".to_string(), 0),
            ]),
        };

        let json = serde_json::to_string(&summary).unwrap();
        let restored: FsSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.files_created, summary.files_created);
        assert_eq!(restored.files_modified, summary.files_modified);
        assert_eq!(restored.files_deleted, summary.files_deleted);
        assert_eq!(restored.total_bytes_written, summary.total_bytes_written);
        assert_eq!(restored.file_sizes, summary.file_sizes);
    }
}
