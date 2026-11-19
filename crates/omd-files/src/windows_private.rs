//! Protected owner-only ACLs, applied by the kernel at object creation. Native
//! relative opens keep creation anchored to the already verified directory.
use cap_std::fs::Dir;
use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
            FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        },
    },
    Win32::{
        Foundation::{LocalFree, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
            GetSecurityDescriptorControl, GetTokenInformation, INHERIT_ONLY_ACE,
            OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GetVolumeInformationByHandleW,
        },
        System::{
            IO::IO_STATUS_BLOCK,
            SystemServices::FILE_PERSISTENT_ACLS,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
};

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct User(Vec<usize>);
impl User {
    fn current() -> io::Result<Self> {
        let mut handle = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful OpenProcessToken returned an owned kernel handle.
        let token = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut length = 0;
        unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length);
        }
        if length == 0 || length > 65536 {
            return Err(io::Error::last_os_error());
        }
        // usize storage keeps TOKEN_USER and its SID naturally aligned.
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buffer))
    }
    fn sid(&self) -> *mut c_void {
        unsafe { (*(self.0.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
    fn descriptor(&self, directory: bool) -> io::Result<Local> {
        let mut text = null_mut();
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allocation = Local(text.cast());
        let mut n = 0;
        while unsafe { *text.add(n) } != 0 {
            n += 1;
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, n) })
            .map_err(|_| denied())?;
        drop(allocation);
        let flags = if directory { "OICI" } else { "" };
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;{flags};FA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Local(descriptor))
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "OMD requires a private profile and private staging on a filesystem supporting persistent Windows ACLs. Choose a new profile in your Windows user directory or an NTFS destination; existing files were not changed.",
    )
}
fn acl_filesystem(file: &impl AsRawHandle) -> io::Result<()> {
    let mut flags = 0;
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(denied());
    }
    Ok(())
}
pub(super) fn create(parent: &Dir, name: &str, directory: bool) -> io::Result<File> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', ':', '\0']) {
        return Err(super::invalid_path());
    }
    acl_filesystem(parent)?;
    let descriptor = User::current()?.descriptor(directory)?;
    // Windows does not treat a leading dot as hidden. Keep engine staging out
    // of ordinary reader/library scans; publish directories themselves remain
    // visible when moved out of this private staging parent.
    let file_attributes = if directory && name.starts_with(".omd-") {
        FILE_ATTRIBUTE_HIDDEN
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let mut name: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(name.len() * 2).map_err(|_| super::invalid_path())?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: descriptor.0.cast(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // FILE_CREATE is exclusive; no existing file or reparse target is opened.
    // No FILE_SHARE_DELETE: the returned directory cannot be substituted while
    // held, matching cap-std's handle-relative traversal and publication model.
    // A directory capability does not need DELETE access to itself. Requesting
    // it makes a second cap-std traversal handle (also denying delete sharing)
    // conflict with this handle, preventing media verification while we own it.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            if directory {
                FILE_ALL_ACCESS & !DELETE
            } else {
                FILE_ALL_ACCESS
            },
            &attributes,
            &mut status,
            null(),
            file_attributes,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            null(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    let file = unsafe { File::from_raw_handle(handle) };
    verify(&file, directory)?;
    Ok(file)
}
pub(super) fn verify(file: &File, directory: bool) -> io::Result<()> {
    acl_filesystem(file)?;
    let user = User::current()?;
    let mut owner = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let allocation = Local(descriptor);
    let mut control = 0;
    let mut revision = 0;
    let mut ace = null_mut();
    // The returned security descriptor owns the SID and ACL pointers until the
    // Local allocation drops. A single effective allow ACE admits only this user.
    let valid = unsafe {
        !owner.is_null()
            && EqualSid(owner, user.sid()) != 0
            && GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
            && !acl.is_null()
            && (*acl).AceCount == 1
            && GetAce(acl, 0, &mut ace) != 0
    };
    if !valid {
        return Err(denied());
    }
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
        return Err(denied());
    }
    let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    let required = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let valid = ace.Header.AceType == 0
        && ace.Mask == FILE_ALL_ACCESS
        && (ace.Header.AceFlags as u32) & (required | INHERIT_ONLY_ACE) == required
        && unsafe { EqualSid((&ace.SidStart as *const u32).cast_mut().cast(), user.sid()) } != 0;
    drop(allocation);
    if valid { Ok(()) } else { Err(denied()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_creation_and_inheritance_do_not_grant_everyone_access() {
        let temp = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(temp.path(), cap_std::ambient_authority()).unwrap();
        let directory = create(&root, "private", true).unwrap();
        verify(&directory, true).unwrap();
        drop(directory);
        let nested = root.open_dir("private").unwrap();
        let file = create(&nested, "secret", false).unwrap();
        verify(&file, false).unwrap();
        assert_eq!(
            create(&nested, "secret", false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        for name in ["../outside", "foo:stream", "foo\\bar"] {
            assert!(create(&nested, name, false).is_err());
        }
        let inherited = nested.create("database").unwrap().into_std();
        let user = User::current().unwrap();
        let mut acl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    inherited.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut acl,
                    null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        let _allocation = Local(descriptor);
        assert_eq!(unsafe { (*acl).AceCount }, 1);
        let mut ace = null_mut();
        assert_ne!(unsafe { GetAce(acl, 0, &mut ace) }, 0);
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        assert_eq!(ace.Mask, FILE_ALL_ACCESS);
        assert_ne!(
            unsafe { EqualSid((&ace.SidStart as *const u32).cast_mut().cast(), user.sid()) },
            0
        );
    }
    #[test]
    fn staging_is_hidden_but_published_directories_are_visible() {
        use std::os::windows::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let root = super::super::Root::open(temp.path()).unwrap();
        let stage = root.create_directory(".omd-stage-v2-test", true).unwrap();
        let publish = stage.create_directory("publish", true).unwrap();
        let stage_path = temp.path().join(".omd-stage-v2-test");
        assert_ne!(
            std::fs::metadata(&stage_path).unwrap().file_attributes() & FILE_ATTRIBUTE_HIDDEN,
            0
        );
        drop(publish);
        let final_path = temp.path().join("Chapter 1");
        std::fs::rename(stage_path.join("publish"), &final_path).unwrap();
        assert_eq!(
            std::fs::metadata(final_path).unwrap().file_attributes() & FILE_ATTRIBUTE_HIDDEN,
            0
        );
    }

    #[test]
    fn private_directory_can_be_reopened_without_allowing_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let parent = Dir::open_ambient_dir(temp.path(), cap_std::ambient_authority()).unwrap();
        let held = create(&parent, "native", true).unwrap();
        let path = temp.path().join("native");
        let reopened = super::super::Root::open(&path).unwrap();
        assert!(std::fs::rename(&path, temp.path().join("replaced")).is_err());
        drop(reopened);
        assert!(std::fs::rename(&path, temp.path().join("replaced")).is_err());
        drop(held);
        std::fs::rename(&path, temp.path().join("replaced")).unwrap();
    }

    #[test]
    fn rejects_unprotected_existing_profile_without_changing_it() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("sentinel"), b"keep").unwrap();
        assert!(super::super::private_profile(temp.path()).is_err());
        assert_eq!(
            std::fs::read(temp.path().join("sentinel")).unwrap(),
            b"keep"
        );
    }
}
