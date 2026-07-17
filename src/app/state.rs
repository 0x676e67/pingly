//! Persistent application state paths.

use std::{
    env, io,
    path::{Path, PathBuf},
};

/// Returns the systemd state directory or Pingly's platform cache directory.
pub(crate) fn directory() -> PathBuf {
    env::var_os("STATE_DIRECTORY")
        .map(PathBuf::from)
        .or_else(|| dirs::cache_dir().map(|path| path.join(env!("CARGO_PKG_NAME"))))
        .unwrap_or_else(|| PathBuf::from(".pingly"))
}

/// Creates a directory for private certificate and account material.
pub(crate) fn prepare_private_directory(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}
