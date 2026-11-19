//! Handle-relative operations for engine-owned files in user-selected roots.
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    path::{Component, Path},
};
#[cfg(windows)]
mod windows_private;

/// The ordinary spelling of a canonical path, for display and API responses.
///
/// On Windows, `std::fs::canonicalize` returns verbatim paths (`\\?\C:\...`,
/// `\\?\UNC\server\share\...`). Engine file operations accept them, but
/// people do not expect them. The prefix is removed only when the ordinary
/// path names the same file; otherwise the verbatim path is kept. Other
/// platforms return the path unchanged.
pub fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    #[cfg(windows)]
    if let Some(simple) = simplify_verbatim(&text) {
        return simple;
    }
    text.into_owned()
}

/// Remove a Windows verbatim prefix when Win32 path normalization cannot change
/// the meaning: a drive or UNC path shorter than MAX_PATH whose components have
/// no reserved device names, invalid characters or trailing dots/spaces.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn simplify_verbatim(path: &str) -> Option<String> {
    let rest = path.strip_prefix(r"\\?\")?;
    let (simple, components) = if let Some(unc) = rest
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case(r"UNC\"))
        .and(rest.get(4..))
    {
        // A server and a share are required; the loop below checks them.
        let mut parts = unc.split('\\');
        if parts.next()?.is_empty() || parts.next()?.is_empty() {
            return None;
        }
        (format!(r"\\{unc}"), unc)
    } else {
        let bytes = rest.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return None;
        }
        (rest.to_owned(), &rest[3..])
    };
    // Win32 path functions reserve MAX_PATH (260) including the terminator.
    if simple.encode_utf16().count() >= 260 {
        return None;
    }
    let components: Vec<&str> = components.split('\\').collect();
    let last = components.len() - 1;
    for (index, component) in components.iter().enumerate() {
        // Only a trailing separator after the final component is ordinary.
        if component.is_empty() {
            if index == last {
                continue;
            }
            return None;
        }
        if matches!(*component, "." | "..")
            || component.ends_with(['.', ' '])
            || component
                .chars()
                .any(|c| c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '/' | '|' | '?' | '*'))
        {
            return None;
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end_matches(' ')
            .to_ascii_uppercase();
        let device = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|n| {
                matches!(
                    n,
                    "0" | "1"
                        | "2"
                        | "3"
                        | "4"
                        | "5"
                        | "6"
                        | "7"
                        | "8"
                        | "9"
                        | "\u{b9}"
                        | "\u{b2}"
                        | "\u{b3}"
                )
            })
        });
        if device {
            return None;
        }
    }
    Some(simple)
}

/// Create a dedicated engine profile before any secrets or database files exist.
/// Windows refuses an existing non-private profile rather than leave previously
/// inherited child ACLs accessible. Download destinations must not call this.
pub fn private_profile(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(invalid_path)?;
    let root = Root::open(parent)?;
    match root.create_directory(name, true) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let directory = root.directory(name)?;
            #[cfg(unix)]
            {
                private_directory_permissions(&directory.0)?;
            }
            #[cfg(windows)]
            windows_private::verify(&directory.0.try_clone()?.into_std_file(), true)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Exclusively create a private file, with access restricted at creation time.
pub fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    let parent = path.parent().ok_or_else(invalid_path)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(invalid_path)?;
    let root = Root::open(parent)?;
    #[cfg(windows)]
    {
        windows_private::create(&root.0, name, false)
    }
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        Ok(root
            .0
            .open_with(
                name,
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .follow(FollowSymlinks::No),
            )?
            .into_std())
    }
}

pub struct Root(Dir);
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub directory: bool,
}

impl Root {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self(Dir::open_ambient_dir(path, ambient_authority())?))
    }
    pub fn identified(path: &Path, marker: &str) -> io::Result<Self> {
        let root = Self::open(path)?;
        let file = root.read_file(&format!(".omd-destination-{marker}"))?;
        let mut bytes = Vec::new();
        file.take(256).read_to_end(&mut bytes)?;
        if bytes != format!("omd:destination@2\n{marker}\n").as_bytes() {
            return Err(io::Error::other("Destination identity does not match"));
        }
        Ok(root)
    }
    pub fn register(path: &Path, marker: &str) -> io::Result<Self> {
        let root = Self::open(path)?;
        let name = format!(".omd-destination-{marker}");
        root.write_new(&name, format!("omd:destination@2\n{marker}\n").as_bytes())?;
        root.sync()?;
        // Windows does not treat a leading dot as hidden. Hiding the marker in
        // the user's folder is cosmetic: a failure never fails registration.
        #[cfg(windows)]
        if let Err(error) = root.hide(&name) {
            tracing::warn!(%error, "could not hide the destination identity marker");
        }
        Ok(root)
    }
    /// Add the hidden attribute to an existing regular file, through a
    /// no-follow handle opened relative to this root.
    #[cfg(windows)]
    fn hide(&self, path: &str) -> io::Result<()> {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_HIDDEN, FILE_BASIC_INFO, FileBasicInfo, SetFileInformationByHandle,
        };
        let (dir, name) = self.parent(path, false)?;
        let file = dir
            .open_with(
                name,
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .follow(FollowSymlinks::No),
            )?
            .into_std();
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid_path());
        }
        // Zero times mean "unchanged"; only the attributes are written.
        let info = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: metadata.file_attributes() | FILE_ATTRIBUTE_HIDDEN,
        };
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileBasicInfo,
                (&info as *const FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn parent(&self, path: &str, create: bool) -> io::Result<(Dir, String)> {
        let parts: Vec<_> = Path::new(path)
            .components()
            .map(|part| match part {
                Component::Normal(s) => s
                    .to_str()
                    .filter(|s| !s.contains(['\\', ':']))
                    .map(str::to_owned)
                    .ok_or_else(invalid_path),
                _ => Err(invalid_path()),
            })
            .collect::<io::Result<_>>()?;
        let (name, parents) = parts.split_last().ok_or_else(invalid_path)?;
        let mut dir = self.0.try_clone()?;
        for part in parents {
            if create {
                match dir.create_dir(part) {
                    Ok(()) => sync(&dir)?,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            dir = dir.open_dir_nofollow(part)?;
        }
        Ok((dir, name.clone()))
    }
    /// Whether any entry (file, folder or link) occupies `path`. Links are not
    /// followed. A missing parent folder means the path is free.
    pub fn exists(&self, path: &str) -> io::Result<bool> {
        let (parent, name) = match self.parent(path, false) {
            Ok(found) => found,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        match parent.symlink_metadata(name) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub fn read_file(&self, path: &str) -> io::Result<std::fs::File> {
        let (dir, name) = self.parent(path, false)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            // A user-created FIFO must not block the engine before metadata can
            // reject it. This flag has no effect on ordinary regular-file reads.
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = dir.open_with(name, &options)?;
        if !file.metadata()?.is_file() {
            return Err(invalid_path());
        }
        Ok(file.into_std())
    }
    pub fn create_new(&self, path: &str) -> io::Result<std::fs::File> {
        let (dir, name) = self.parent(path, true)?;
        Ok(dir
            .open_with(
                name,
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .follow(FollowSymlinks::No),
            )?
            .into_std())
    }
    pub fn write_new(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        let mut file = self.create_new(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let (dir, _) = self.parent(path, false)?;
        sync(&dir)
    }
    pub fn hash(&self, path: &str) -> io::Result<(u64, String)> {
        hash_file(self.read_file(path)?)
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
    pub fn directory(&self, path: &str) -> io::Result<Self> {
        let (parent, name) = self.parent(path, false)?;
        Ok(Self(parent.open_dir_nofollow(name)?))
    }
    pub fn create_directory(&self, path: &str, private: bool) -> io::Result<Self> {
        let (parent, name) = self.parent(path, true)?;
        #[cfg(windows)]
        if private {
            return Ok(Self(Dir::from_std_file(windows_private::create(
                &parent, &name, true,
            )?)));
        }
        let builder = cap_std::fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use cap_std::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(if private { 0o700 } else { 0o755 });
            builder
        };
        parent.create_dir_with(&name, &builder)?;
        sync(&parent)?;
        Ok(Self(parent.open_dir_nofollow(name)?))
    }
    pub fn open_resume(&self, path: &str) -> io::Result<std::fs::File> {
        let (dir, name) = self.parent(path, false)?;
        let file = dir.open_with(
            name,
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .follow(FollowSymlinks::No),
        )?;
        if !file.metadata()?.is_file() {
            return Err(invalid_path());
        }
        Ok(file.into_std())
    }
    /// Open an already produced file for verification and a durability barrier.
    /// Windows requires write access for FlushFileBuffers. Unlike a resumable
    /// transfer, a missing completed output must never be created by this open.
    pub fn open_existing_read_write(&self, path: &str) -> io::Result<std::fs::File> {
        let (dir, name) = self.parent(path, false)?;
        let file = dir.open_with(
            name,
            OpenOptions::new()
                .read(true)
                .write(true)
                .follow(FollowSymlinks::No),
        )?;
        if !file.metadata()?.is_file() {
            return Err(invalid_path());
        }
        Ok(file.into_std())
    }
    /// Remove one entry without following it. Only engine-owned staged paths may
    /// be discarded automatically; acquired files require a verified removal plan.
    pub fn remove_file(&self, path: &str) -> io::Result<()> {
        let (parent, name) = self.parent(path, false)?;
        parent.remove_file(name)?;
        sync(&parent)
    }
    /// List one directory without following symlinks or accepting special files.
    /// Callers control traversal and persist their own bounded batches.
    pub fn entries(&self) -> io::Result<impl Iterator<Item = io::Result<Entry>>> {
        Ok(self.0.entries()?.map(|entry| {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_path())?;
            let kind = entry.file_type()?;
            if !kind.is_dir() && !kind.is_file() {
                return Err(invalid_path());
            }
            Ok(Entry {
                name,
                directory: kind.is_dir(),
            })
        }))
    }
    /// Unlike recursive removal, a concurrent added file makes this fail safely.
    pub fn remove_empty_directory(&self, path: &str) -> io::Result<()> {
        let (parent, name) = self.parent(path, false)?;
        parent.open_dir_nofollow(&name)?;
        parent.remove_dir(&name)?;
        sync(&parent)
    }
    pub fn remove_directory(&self, path: &str) -> io::Result<()> {
        let (parent, name) = self.parent(path, false)?;
        // Open first: reject symlinks and remove this directory handle's contents.
        parent.open_dir_nofollow(name)?.remove_open_dir_all()?;
        sync(&parent)
    }
    pub fn publish(&self, path: &str, destination: &Self, target: &str) -> io::Result<()> {
        let (from, name) = self.parent(path, false)?;
        let (to, target) = destination.parent(target, true)?;
        rename_exclusive(&from, &name, &to, &target)?;
        sync(&from)?;
        sync(&to)
    }
    pub fn sync(&self) -> io::Result<()> {
        sync(&self.0)
    }
}

fn rename_exclusive(from: &Dir, name: &str, to: &Dir, target: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let name = std::ffi::CString::new(name)?;
        let target = std::ffi::CString::new(target)?;
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                from.as_raw_fd(),
                name.as_ptr(),
                to.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let result = unsafe {
            // Use the kernel operation directly: some supported static musl
            // toolchains declare renameat2 without exporting its libc wrapper.
            // Never replace this with a check-then-rename fallback; publication
            // must keep the kernel's atomic no-overwrite guarantee.
            libc::syscall(
                libc::SYS_renameat2,
                from.as_raw_fd(),
                name.as_ptr(),
                to.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
        // cap-std directory handles deny FILE_SHARE_DELETE. Keep both open
        // throughout path retrieval and MoveFileEx so they cannot be replaced.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetFinalPathNameByHandleW(
                handle: *mut std::ffi::c_void,
                path: *mut u16,
                length: u32,
                flags: u32,
            ) -> u32;
            fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        }
        let full = |dir: &Dir, name: &str| -> io::Result<Vec<u16>> {
            let mut buffer = vec![0u16; 32768];
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    dir.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    0,
                )
            };
            if n == 0 || n as usize >= buffer.len() {
                return Err(io::Error::last_os_error());
            }
            buffer.truncate(n as usize);
            buffer.push(b'\\' as u16);
            buffer.extend(std::ffi::OsStr::new(name).encode_wide());
            buffer.push(0);
            Ok(buffer)
        };
        let source = full(from, name)?;
        let destination = full(to, target)?;
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 8) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
fn invalid_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Expected an ordinary relative file path without symlinks",
    )
}
#[cfg(unix)]
fn private_directory_permissions(dir: &Dir) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Linux traversal handles may be O_PATH, which fchmod cannot use. Reopen
    // the same held directory, rather than resolving a substitutable path.
    dir.open_with(".", OpenOptions::new().read(true))?
        .into_std()
        .set_permissions(std::fs::Permissions::from_mode(0o700))
}
fn sync(dir: &Dir) -> io::Result<()> {
    #[cfg(unix)]
    // Traversal capabilities may use O_PATH on Linux. They identify the right
    // directory but fsync rejects them with EBADF. Open that same directory for
    // reading relative to the held capability; never resolve its ambient path.
    dir.open_with(".", OpenOptions::new().read(true))?
        .sync_all()?;
    #[cfg(windows)]
    let _ = dir;
    Ok(())
}
pub fn hash_file(mut file: std::fs::File) -> io::Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut size = 0;
    let mut bytes = [0u8; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
        size += n as u64;
    }
    Ok((size, hex::encode(hash.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verbatim_windows_paths_display_in_their_ordinary_form_only_when_equivalent() {
        for (verbatim, simple) in [
            (
                r"\\?\C:\Users\OMDGuiQA\Downloads\OMD",
                r"C:\Users\OMDGuiQA\Downloads\OMD",
            ),
            (r"\\?\d:\", r"d:\"),
            (
                r"\\?\C:\Music\Show [c6257dbadc]",
                r"C:\Music\Show [c6257dbadc]",
            ),
            (
                r"\\?\C:\Users\Zoë\Musik\Pödcasts",
                r"C:\Users\Zoë\Musik\Pödcasts",
            ),
            (
                r"\\?\C:\CONSOLE\COM10\LPT\.hidden",
                r"C:\CONSOLE\COM10\LPT\.hidden",
            ),
            (r"\\?\UNC\nas\media\OMD", r"\\nas\media\OMD"),
            (r"\\?\unc\nas\media", r"\\nas\media"),
        ] {
            assert_eq!(
                simplify_verbatim(verbatim).as_deref(),
                Some(simple),
                "{verbatim}"
            );
        }
        // MAX_PATH (260) includes the terminator: 259 characters is ordinary.
        let long = format!(r"\\?\C:\{}", "a".repeat(257));
        for kept in [
            // Not verbatim, or not a drive/UNC path.
            r"C:\Users\OMD",
            "/home/omd/Downloads/OMD",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\OMD",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\OMD",
            r"\\?\C:",
            r"\\?\UNC\nas",
            r"\\?\UNC\\share",
            // Win32 would rewrite these names.
            r"\\?\C:\Downloads\NUL",
            r"\\?\C:\Downloads\con.txt",
            r"\\?\C:\Downloads\Aux \x",
            r"\\?\C:\Downloads\COM1",
            r"\\?\C:\Downloads\lpt¹",
            r"\\?\C:\Downloads\trailing.",
            r"\\?\C:\Downloads\trailing ",
            r"\\?\C:\Downloads\..\x",
            r"\\?\C:\Downloads\.\x",
            r"\\?\C:\Downloads\\x",
            r"\\?\C:\Downloads\a:stream",
            r"\\?\C:\Downloads/x",
            r"\\?\C:\Downloads\what?",
            &long,
        ] {
            assert_eq!(simplify_verbatim(kept), None, "{kept}");
        }
        assert_eq!(
            simplify_verbatim(&format!(r"\\?\C:\{}", "a".repeat(256))).map(|s| s.len()),
            Some(259)
        );
        #[cfg(not(windows))]
        assert_eq!(
            display_path(Path::new(r"\\?\C:\Users")),
            r"\\?\C:\Users",
            "only Windows interprets verbatim prefixes"
        );
    }
    #[test]
    fn exists_reports_any_entry_without_following_links_or_creating_parents() {
        let temp = tempfile::tempdir().unwrap();
        let root = Root::open(temp.path()).unwrap();
        assert!(!root.exists("Show/Episode").unwrap());
        assert!(!temp.path().join("Show").exists());
        root.create_directory("Show/Episode", false).unwrap();
        assert!(root.exists("Show/Episode").unwrap());
        root.write_new("Show/file.txt", b"x").unwrap();
        assert!(root.exists("Show/file.txt").unwrap());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/nonexistent", temp.path().join("Show/link")).unwrap();
            assert!(root.exists("Show/link").unwrap());
        }
        assert!(root.exists("../outside").is_err());
    }
    #[test]
    fn destination_marker_is_identified_and_hidden_on_windows() {
        let temp = tempfile::tempdir().unwrap();
        Root::register(temp.path(), "abc123").unwrap();
        Root::identified(temp.path(), "abc123").unwrap();
        assert!(Root::identified(temp.path(), "other").is_err());
        assert_eq!(
            Root::register(temp.path(), "abc123")
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let attributes = std::fs::metadata(temp.path().join(".omd-destination-abc123"))
                .unwrap()
                .file_attributes();
            assert_ne!(
                attributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN,
                0
            );
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn private_permissions_reopen_path_handles_without_following_replacements() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path().join("profile");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&profile).unwrap();
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&profile)
            .unwrap();
        std::fs::rename(&profile, &moved).unwrap();
        std::fs::create_dir(&profile).unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(moved.join("sentinel"), b"retained profile data").unwrap();
        private_directory_permissions(&Dir::from_std_file(handle)).unwrap();
        assert_eq!(
            std::fs::metadata(&moved).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&profile).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::read(moved.join("sentinel")).unwrap(),
            b"retained profile data"
        );
    }
    #[test]
    fn completed_output_flush_requires_an_existing_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = Root::open(temp.path()).unwrap();
        assert_eq!(
            root.open_existing_read_write("missing.mp4")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(!temp.path().join("missing.mp4").exists());
        root.write_new("completed.mp4", b"verified media fixture")
            .unwrap();
        let file = root.open_existing_read_write("completed.mp4").unwrap();
        file.sync_all().unwrap();
        assert_eq!(hash_file(file).unwrap().0, 22);
        root.create_directory("directory", true).unwrap();
        assert!(root.open_existing_read_write("directory").is_err());
    }
    #[test]
    fn nested_publication_syncs_each_parent_and_preserves_collisions() {
        let temp = tempfile::tempdir().unwrap();
        let root = Root::register(temp.path(), "nested").unwrap();
        root.write_new("series/chapter/page.jpg", b"complete page")
            .unwrap();
        assert_eq!(root.hash("series/chapter/page.jpg").unwrap().0, 13);
        root.directory("series/chapter").unwrap().sync().unwrap();
        assert_eq!(
            root.write_new("series/chapter/page.jpg", b"replacement")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        root.remove_file("series/chapter/page.jpg").unwrap();
        assert!(root.read_file("series/chapter/page.jpg").is_err());
    }
    #[test]
    fn private_profile_and_token_creation_are_exclusive_and_preserve_data() {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path().join("profile");
        private_profile(&profile).unwrap();
        let token = profile.join("instance.tmp");
        let mut file = create_private_file(&token).unwrap();
        file.write_all(b"private fixture token").unwrap();
        drop(file);
        private_profile(&profile).unwrap();
        assert_eq!(
            create_private_file(&token).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&token).unwrap(), b"private fixture token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&profile).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&token).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::os::unix::fs::symlink(&profile, temp.path().join("link")).unwrap();
            assert!(private_profile(&temp.path().join("link")).is_err());
        }
    }
    #[test]
    fn identity_detects_empty_mountpoint_and_registration_does_not_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("disk");
        std::fs::create_dir(&path).unwrap();
        Root::register(&path, "owned").unwrap();
        assert!(Root::register(&path, "owned").is_err());
        Root::identified(&path, "owned").unwrap();
        std::fs::rename(&path, temp.path().join("detached")).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(Root::identified(&path, "owned").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn handles_do_not_follow_replaced_root_or_symlink_parents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("disk");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let root = Root::register(&path, "owned").unwrap();
        std::os::unix::fs::symlink(&outside, path.join("link")).unwrap();
        assert!(root.write_new("link/unsafe", b"x").is_err());
        assert!(root.read_file("../outside/unsafe").is_err());
        std::fs::rename(&path, temp.path().join("detached")).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        root.write_new("owned-file", b"safe").unwrap();
        assert!(!outside.join("owned-file").exists());
        assert!(temp.path().join("detached/owned-file").is_file());
    }
}
