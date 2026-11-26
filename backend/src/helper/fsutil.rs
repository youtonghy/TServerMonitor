//! File primitives for the helper: content hashes, confined path resolution (no symlinks, no
//! escape), timestamped backups and atomic replacement.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ops::proto::{OpError, OpResult};

/// Backups kept per domain.
const KEEP_BACKUPS: usize = 50;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Resolves `rel` (already validated component by component) under `root`. Every existing
/// component must be a real directory or regular file, never a symlink, so the result cannot
/// point outside `root`. The last component may not exist yet.
pub fn confined(root: &Path, rel: &[String]) -> OpResult<PathBuf> {
    let mut p = root.to_path_buf();
    for (i, c) in rel.iter().enumerate() {
        p.push(c);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(OpError::invalid(format!(
                    "{} 是符号链接，拒绝操作",
                    p.display()
                )));
            }
            Ok(m) if i + 1 < rel.len() && !m.is_dir() => {
                return Err(OpError::invalid(format!("{} 不是目录", p.display())));
            }
            Ok(m) if i + 1 == rel.len() && !m.is_file() => {
                return Err(OpError::invalid(format!("{} 不是普通文件", p.display())));
            }
            Ok(_) => {}
            Err(_) if i + 1 == rel.len() => {}
            Err(_) => {
                return Err(OpError::invalid(format!("{} 不存在", p.display())));
            }
        }
    }
    Ok(p)
}

/// A file's state before a change. `saved = None` means the file did not exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub path: PathBuf,
    pub saved: Option<PathBuf>,
}

fn sanitize(p: &Path) -> String {
    p.to_string_lossy()
        .trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Copies `path` (if it exists) into `<state_dir>/backups/<domain>/` before a change.
pub fn backup(state_dir: &Path, domain: &str, path: &Path) -> Result<Backup> {
    let dir = state_dir.join("backups").join(domain);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let saved = match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {
            let name = format!(
                "{}-{}-{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%S%.3f"),
                std::process::id(),
                sanitize(path)
            );
            let dst = dir.join(name);
            std::fs::copy(path, &dst).with_context(|| format!("backing up {}", path.display()))?;
            Some(dst)
        }
        Ok(_) => anyhow::bail!("{} is not a regular file", path.display()),
        Err(_) => None,
    };
    prune(&dir);
    Ok(Backup {
        path: path.to_path_buf(),
        saved,
    })
}

fn prune(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut names: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    if names.len() <= KEEP_BACKUPS {
        return;
    }
    names.sort();
    for p in &names[..names.len() - KEEP_BACKUPS] {
        let _ = std::fs::remove_file(p);
    }
}

/// Puts the file back exactly as it was (or removes it if it did not exist).
pub fn restore(b: &Backup) -> Result<()> {
    match &b.saved {
        Some(saved) => {
            let data =
                std::fs::read(saved).with_context(|| format!("reading {}", saved.display()))?;
            atomic_write(&b.path, &data)
        }
        None => match std::fs::remove_file(&b.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", b.path.display())),
        },
    }
}

/// Writes through a temporary file in the same directory and renames it over `path`, keeping
/// the existing file's mode and owner (new files get 0644).
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let dir = path.parent().context("path has no parent")?;
    let old = std::fs::symlink_metadata(path).ok().filter(|m| m.is_file());
    let tmp = dir.join(format!(
        ".{}.tsm-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        uuid::Uuid::new_v4().simple()
    ));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
        let mode = old.as_ref().map_or(0o644, |m| m.mode() & 0o7777);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        if let Some(m) = &old {
            // keep ownership; only possible (and needed) as root
            let _ = std::os::unix::fs::chown(&tmp, Some(m.uid()), Some(m.gid()));
        }
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        anyhow::Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_and_restore_are_byte_identical() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("site.conf");
        let original = b"server {\n  listen 80;\n}\n\xff";
        std::fs::write(&f, original).unwrap();
        let b = backup(&d.path().join("state"), "nginx", &f).unwrap();
        atomic_write(&f, b"broken").unwrap();
        restore(&b).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), original);

        let new = d.path().join("new.conf");
        let b = backup(&d.path().join("state"), "nginx", &new).unwrap();
        assert!(b.saved.is_none());
        atomic_write(&new, b"x").unwrap();
        restore(&b).unwrap();
        assert!(!new.exists());
    }

    #[test]
    fn confined_refuses_symlinks_and_non_files() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        std::fs::create_dir(root.join("conf.d")).unwrap();
        std::fs::write(root.join("conf.d/a.conf"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("conf.d/evil.conf")).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("linkdir")).unwrap();
        let rel = |s: &str| crate::ops::validate::rel_path(s).unwrap();
        assert!(confined(root, &rel("conf.d/a.conf")).is_ok());
        assert!(confined(root, &rel("conf.d/new.conf")).is_ok());
        assert!(confined(root, &rel("conf.d/evil.conf")).is_err());
        assert!(confined(root, &rel("linkdir/passwd")).is_err());
        assert!(confined(root, &rel("conf.d")).is_err());
        assert!(confined(root, &rel("missing/x.conf")).is_err());
    }
}
