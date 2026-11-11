//! Duplicate-file finder: group by size, then by a quick hash of the head, then by a full
//! hash, and finally confirm byte-for-byte so a hash collision can never cost anyone a file.

use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct DupFile {
    pub path: PathBuf,
    pub modified: Option<SystemTime>,
}

#[derive(Clone, Debug)]
pub struct DupGroup {
    pub size: u64,
    /// Oldest file first.
    pub files: Vec<DupFile>,
}

impl DupGroup {
    /// Space freed if all but one copy is removed.
    pub fn wasted(&self) -> u64 {
        self.size * (self.files.len() as u64 - 1)
    }
}

fn hash_file(path: &Path, limit: Option<usize>) -> Option<u64> {
    let mut f = File::open(path).ok()?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut left = limit.unwrap_or(usize::MAX);
    while left > 0 {
        let want = buf.len().min(left);
        let n = f.read(&mut buf[..want]).ok()?;
        if n == 0 {
            break;
        }
        buf[..n].hash(&mut h);
        left -= n;
    }
    Some(h.finish())
}

fn same_bytes(a: &Path, b: &Path) -> bool {
    let (Ok(mut fa), Ok(mut fb)) = (File::open(a), File::open(b)) else {
        return false;
    };
    let (mut ba, mut bb) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    loop {
        let Ok(na) = fa.read(&mut ba) else {
            return false;
        };
        let mut nb = 0;
        while nb < na {
            match fb.read(&mut bb[nb..na]) {
                Ok(0) | Err(_) => return false,
                Ok(n) => nb += n,
            }
        }
        if na == 0 {
            // `a` is exhausted: equal only if `b` is too.
            return matches!(fb.read(&mut bb[..1]), Ok(0));
        }
        if ba[..na] != bb[..na] {
            return false;
        }
    }
}

const SKIP_TREES: &[&str] = &[
    "node_modules",
    ".git",
    "site-packages",
    ".venv",
    "venv",
    ".steam",
    ".wine",
    "__pycache__",
];

type Candidate = (PathBuf, u64, Option<SystemTime>);

/// Hash, then byte-compare, the files that share one size. Returns the confirmed duplicate sets.
fn confirm_group(size: u64, files: Vec<Candidate>) -> Vec<DupGroup> {
    let mut groups = Vec::new();
    let mut by_head: HashMap<u64, Vec<_>> = HashMap::new();
    for f in files {
        if let Some(h) = hash_file(&f.0, Some(64 * 1024)) {
            by_head.entry(h).or_default().push(f);
        }
    }
    for same_head in by_head.into_values().filter(|v| v.len() > 1) {
        let mut by_full: HashMap<u64, Vec<_>> = HashMap::new();
        for f in same_head {
            if let Some(h) = hash_file(&f.0, None) {
                by_full.entry(h).or_default().push(f);
            }
        }
        for same_hash in by_full.into_values().filter(|v| v.len() > 1) {
            // Confirm against real bytes; a hash match alone is never enough to delete on.
            let mut clusters: Vec<Vec<(PathBuf, u64, Option<SystemTime>)>> = Vec::new();
            for f in same_hash {
                match clusters.iter_mut().find(|c| same_bytes(&c[0].0, &f.0)) {
                    Some(c) => c.push(f),
                    None => clusters.push(vec![f]),
                }
            }
            for mut c in clusters.into_iter().filter(|c| c.len() > 1) {
                c.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
                groups.push(DupGroup {
                    size,
                    files: c
                        .into_iter()
                        .map(|(path, _, modified)| DupFile { path, modified })
                        .collect(),
                });
            }
        }
    }
    groups
}

/// Returns the groups (largest waste first) and the number of files looked at.
pub fn scan(root: &Path, min_size: u64, include_hidden: bool) -> (Vec<DupGroup>, usize) {
    let mut scanned = 0;
    let mut by_size: HashMap<u64, Vec<Candidate>> = HashMap::new();
    let mut seen_inodes = std::collections::HashSet::new();
    for e in walkdir::WalkDir::new(root)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Copies in these trees are expected at their exact paths by tools and games.
            let skipped_tree = e.file_type().is_dir() && SKIP_TREES.contains(&name.as_ref());
            e.depth() == 0
                || (!skipped_tree
                    && !crate::util::excluded(e.path())
                    && (include_hidden || !name.starts_with('.')))
        })
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        scanned += 1;
        let Ok(m) = e.metadata() else { continue };
        if m.len() < min_size.max(1) {
            continue;
        }
        // Hard links to the same data aren't wasted space and deleting one frees nothing.
        if !seen_inodes.insert((m.dev(), m.ino())) {
            continue;
        }
        by_size
            .entry(m.len())
            .or_default()
            .push((e.into_path(), m.len(), m.modified().ok()));
    }

    // Hashing is disk- and CPU-bound and every size group is independent: spread them over threads.
    let candidates: Vec<(u64, Vec<Candidate>)> =
        by_size.into_iter().filter(|(_, v)| v.len() > 1).collect();
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(8);
    let mut lanes: Vec<Vec<(u64, Vec<Candidate>)>> = (0..threads).map(|_| Vec::new()).collect();
    // Deal the biggest groups out first so the lanes finish at about the same time.
    let mut candidates = candidates;
    candidates.sort_by_key(|(size, v)| std::cmp::Reverse(size * v.len() as u64));
    for (i, c) in candidates.into_iter().enumerate() {
        lanes[i % threads].push(c);
    }
    let mut groups: Vec<DupGroup> = std::thread::scope(|sc| {
        let handles: Vec<_> = lanes
            .into_iter()
            .map(|lane| {
                sc.spawn(move || {
                    lane.into_iter()
                        .flat_map(|(size, files)| confirm_group(size, files))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    groups.sort_by_key(|g| std::cmp::Reverse(g.wasted()));
    (groups, scanned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_duplicates_but_not_lookalikes_or_hardlinks() {
        let dir = std::env::temp_dir().join(format!("dupes-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a"), b"hello world").unwrap();
        std::fs::write(dir.join("sub/b"), b"hello world").unwrap();
        std::fs::write(dir.join("c"), b"hello_world").unwrap(); // same size, different bytes
        std::fs::hard_link(dir.join("a"), dir.join("a-link")).unwrap();
        let (groups, scanned) = scan(&dir, 1, false);
        assert_eq!(scanned, 4);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].files.len(), 2);
        assert_eq!(groups[0].wasted(), 11);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
