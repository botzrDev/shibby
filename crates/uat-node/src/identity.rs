//! Persistent node identity: one Ed25519 secret at `$UAT_HOME/identity.key`.

use crate::{public_key_to_node_id, NodeError};
use iroh::SecretKey;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uat_core::NodeId;

/// Default directory name under the home directory when `UAT_HOME` is unset.
pub const DEFAULT_UAT_DIR: &str = ".uat";

/// Filename for the secret key inside `UAT_HOME`.
pub const IDENTITY_FILE: &str = "identity.key";

/// Required unix mode bits for the identity file (`0600`).
pub const REQUIRED_MODE: u32 = 0o600;

/// Errors loading or creating identity.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Home / `UAT_HOME` could not be resolved.
    #[error("cannot resolve UAT home directory")]
    NoHome,

    /// Identity file exists but mode is not exactly `0600`.
    #[error("identity key permissions are {mode:o}; refusing to start (want {REQUIRED_MODE:o})")]
    InsecurePermissions { mode: u32 },

    /// Identity file length was not 32 bytes.
    #[error("identity key file must be exactly 32 bytes")]
    BadKeyLength,

    /// Filesystem I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Key bytes were rejected by iroh.
    #[error(transparent)]
    Node(#[from] NodeError),
}

/// Resolve `$UAT_HOME`, or `~/.uat` when unset.
pub fn uat_home() -> Result<PathBuf, IdentityError> {
    if let Ok(path) = std::env::var("UAT_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = dirs_next_home().ok_or(IdentityError::NoHome)?;
    Ok(home.join(DEFAULT_UAT_DIR))
}

fn dirs_next_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Path to the identity key file under `uat_home()`.
pub fn identity_path() -> Result<PathBuf, IdentityError> {
    Ok(uat_home()?.join(IDENTITY_FILE))
}

/// Loaded identity: secret (iroh) plus stable [`NodeId`].
#[derive(Clone, Debug)]
pub struct Identity {
    secret: SecretKey,
    node_id: NodeId,
}

impl Identity {
    /// The iroh secret key (only `uat-node` holds this).
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// Stable public node id.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }
}

/// Load `$UAT_HOME/identity.key`, or generate and write it at mode `0600`.
///
/// Refuses to start if an existing file is not mode `0600`.
pub fn load_or_create() -> Result<Identity, IdentityError> {
    let path = identity_path()?;
    load_or_create_at(&path)
}

/// Same as [`load_or_create`] for an explicit path (tests).
pub fn load_or_create_at(path: &Path) -> Result<Identity, IdentityError> {
    if path.exists() {
        load_at(path)
    } else {
        create_at(path)
    }
}

fn load_at(path: &Path) -> Result<Identity, IdentityError> {
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != REQUIRED_MODE {
        return Err(IdentityError::InsecurePermissions { mode });
    }
    let mut file = fs::File::open(path)?;
    let mut buf = [0u8; 32];
    let n = file.read(&mut buf)?;
    if n != 32 {
        return Err(IdentityError::BadKeyLength);
    }
    // Ensure no extra bytes.
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(IdentityError::BadKeyLength);
    }
    let secret = SecretKey::from_bytes(&buf);
    let node_id = public_key_to_node_id(&secret.public());
    Ok(Identity { secret, node_id })
}

fn create_at(path: &Path) -> Result<Identity, IdentityError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let secret = SecretKey::generate();
    let bytes = secret.to_bytes();

    // Prefer atomic create with explicit mode. Some filesystems reject `mode` on
    // open; fall back to write + chmod, then verify.
    let write_result = (|| -> Result<(), IdentityError> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true).mode(REQUIRED_MODE);
        match opts.open(path) {
            Ok(mut file) => {
                file.write_all(&bytes)?;
                file.sync_all()?;
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(REQUIRED_MODE);
                fs::set_permissions(path, perms)?;
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    })();
    write_result?;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != REQUIRED_MODE {
        return Err(IdentityError::InsecurePermissions { mode });
    }
    let node_id = public_key_to_node_id(&secret.public());
    Ok(Identity { secret, node_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_key_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/identity-test");
        let _ = fs::create_dir_all(&dir);
        dir.join(format!("uat-id-{nanos}.key"))
    }

    #[test]
    fn restart_yields_same_public_key() {
        let path = temp_key_path();
        let first = load_or_create_at(&path).expect("create");
        let id1 = first.node_id();
        drop(first);
        let second = load_or_create_at(&path).expect("reload");
        assert_eq!(second.node_id(), id1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_mode_refuses_to_start() {
        let path = temp_key_path();
        let created = load_or_create_at(&path).expect("create");
        drop(created);
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        let err = load_or_create_at(&path).expect_err("must refuse");
        match err {
            IdentityError::InsecurePermissions { mode } => assert_eq!(mode, 0o644),
            other => panic!("unexpected {other}"),
        }
        let _ = fs::remove_file(&path);
    }
}
