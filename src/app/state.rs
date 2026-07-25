//! Persistent application state paths.

use std::{
    env, io,
    path::{Path, PathBuf},
};

/// Returns the systemd state directory or Pingly's platform cache directory.
pub(crate) fn directory() -> PathBuf {
    let dir = env!("CARGO_PKG_NAME");
    env::var_os("STATE_DIRECTORY")
        .map(PathBuf::from)
        .or_else(|| dirs::cache_dir().map(|path| path.join(dir)))
        .unwrap_or_else(|| PathBuf::from(dir))
}

/// Creates a directory for private certificate and account material.
///
/// # Errors
///
/// Returns an error when the directory cannot be created or its Unix permissions cannot be set to
/// owner-only access.
pub(crate) fn prepare_private_directory(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}
