//! Recover only this user's OMD helper profiles whose creating process is dead.
//! Creation time disambiguates PID reuse; active profiles are never recycled.
//! One per-user lock across sessions serializes every OMD profile creation and
//! deletion, so guardians that start together never delete the same abandoned
//! profile at once. The lock only coordinates; the creator identity checks
//! below still decide which profiles may be deleted.
use super::{Local, Result, check, descriptor, invalid, owned, sid_text, wide};
use std::{
    marker::PhantomData,
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{
        Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
        FreeSid,
        Isolation::*,
        OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::READ_CONTROL,
    System::{Registry::*, Threading::*},
};

/// Longest wait for another guardian's profile step. Holders release the lock
/// before any helper runs, so expiry means something is wrong: fail closed.
const LOCK_WAIT: Duration = Duration::from_secs(15);

/// Global mutex named for this user, with verified ownership. New objects grant
/// access only to this user; existing objects retain their creator's DACL.
pub struct ProfileLock(OwnedHandle);
/// Ownership proof. It is not Send: ReleaseMutex must run on the acquiring thread.
pub struct Held<'a>(&'a ProfileLock, PhantomData<*const ()>);
impl ProfileLock {
    pub fn open(user: &str) -> Result<Self> {
        Self::named(&format!("Global\\OMD.V2.Helper.Profiles.{user}"), user)
    }
    fn named(name: &str, user: &str) -> Result<Self> {
        let sd = descriptor(&format!("O:{user}D:P(A;;GA;;;{user})"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // An existing object of another type fails with ERROR_INVALID_HANDLE;
        // one that withholds this access fails with ERROR_ACCESS_DENIED.
        let handle = owned(unsafe {
            CreateMutexExW(
                &attributes,
                wide(name).as_ptr(),
                0,
                SYNCHRONIZATION_SYNCHRONIZE | MUTEX_MODIFY_STATE | READ_CONTROL,
            )
        })?;
        // An existing mutex keeps its creator's descriptor. Use it only if this
        // user owns it, whether it was just created or already existed.
        let (mut owner, mut security) = (null_mut(), null_mut());
        let status = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut security,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let _security = Local(security);
        if owner.is_null() || sid_text(owner)? != user {
            return Err(invalid());
        }
        Ok(Self(handle))
    }
    pub fn acquire(&self) -> Result<Held<'_>> {
        self.acquire_within(LOCK_WAIT)
    }
    fn acquire_within(&self, wait: Duration) -> Result<Held<'_>> {
        let millis = u32::try_from(wait.as_millis()).map_or(INFINITE - 1, |m| m.min(INFINITE - 1));
        match unsafe { WaitForSingleObject(self.0.as_raw_handle(), millis) } {
            // WAIT_ABANDONED: a guardian died holding the lock and ownership passes
            // here. Its step may be half done; recovery re-reads every profile.
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Held(self, PhantomData)),
            WAIT_TIMEOUT => Err(std::io::Error::from_raw_os_error(WAIT_TIMEOUT as i32)),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
}
impl Drop for Held<'_> {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0.0.as_raw_handle());
        }
    }
}

pub fn birth(handle: HANDLE) -> Result<u64> {
    let (mut create, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    check(unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user) })?;
    Ok((u64::from(create.dwHighDateTime) << 32) | u64::from(create.dwLowDateTime))
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn text(key: HKEY, name: &str) -> Result<String> {
    let mut bytes = vec![0u16; 512];
    let mut size = (bytes.len() * 2) as u32;
    let mut kind = 0;
    let result = unsafe {
        RegGetValueW(
            key,
            null(),
            wide(name).as_ptr(),
            RRF_RT_REG_SZ,
            &mut kind,
            bytes.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32));
    }
    if size < 2 || size as usize > bytes.len() * 2 || !size.is_multiple_of(2) {
        return Err(invalid());
    }
    String::from_utf16(&bytes[..size as usize / 2 - 1]).map_err(|_| invalid())
}
/// Runs only under the profile lock. Candidates are read and validated after
/// acquiring it, and no OMD guardian creates or deletes a profile until it is
/// released, so each validated profile is still abandoned when deleted.
pub fn recover(_lock: &Held<'_>) -> Result<()> {
    let mut raw = null_mut();
    let result = unsafe {
        RegOpenKeyExW(HKEY_CURRENT_USER,wide("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings").as_ptr(),0,KEY_READ,&mut raw)
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32));
    }
    let mapping = Key(raw);
    let mut candidates = Vec::new();
    let mut complete = false;
    for index in 0..16384 {
        let mut name = [0u16; 256];
        let mut size = name.len() as u32;
        let result = unsafe {
            RegEnumKeyExW(
                mapping.0,
                index,
                name.as_mut_ptr(),
                &mut size,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if result == ERROR_NO_MORE_ITEMS {
            complete = true;
            break;
        }
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32));
        }
        let name = String::from_utf16(&name[..size as usize]).map_err(|_| invalid())?;
        let mut raw = null_mut();
        if unsafe { RegOpenKeyExW(mapping.0, wide(&name).as_ptr(), 0, KEY_READ, &mut raw) } != 0 {
            continue;
        }
        let key = Key(raw);
        let Ok(moniker) = text(key.0, "Moniker") else {
            continue;
        };
        let Some(rest) = moniker.strip_prefix("omd.helper.v2.p") else {
            continue;
        };
        let Some((pid, rest)) = rest.split_once(".t") else {
            continue;
        };
        let Some((stamp, nonce)) = rest.split_once('.') else {
            continue;
        };
        if nonce.len() != 16 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) || stamp.len() != 16 {
            continue;
        }
        let (Ok(pid), Ok(stamp)) = (pid.parse::<u32>(), u64::from_str_radix(stamp, 16)) else {
            continue;
        };
        match owned(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        }) {
            Ok(process) => {
                if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } == WAIT_TIMEOUT {
                    match birth(process.as_raw_handle()) {
                        Ok(actual) if actual != stamp => {}
                        _ => continue,
                    }
                }
            }
            Err(error) if error.raw_os_error() != Some(ERROR_INVALID_PARAMETER as i32) => continue,
            Err(_) => {}
        }
        let mut sid = null_mut();
        if unsafe { DeriveAppContainerSidFromAppContainerName(wide(&moniker).as_ptr(), &mut sid) }
            < 0
        {
            continue;
        }
        let matches = sid_text(sid).ok().as_deref() == Some(name.as_str());
        unsafe {
            FreeSid(sid);
        }
        if matches {
            candidates.push(moniker);
        }
    }
    if !complete {
        return Err(std::io::Error::other(
            "AppContainer profile reconciliation budget exceeded",
        ));
    }
    drop(mapping);
    for moniker in candidates {
        let result = unsafe { DeleteAppContainerProfile(wide(&moniker).as_ptr()) };
        // The profile may already be gone, for example removed from another
        // session. Every other failure, including access denied, fails closed.
        if result < 0 && ![2u32, 1168u32].contains(&((result as u32) & 0xffff)) {
            return Err(std::io::Error::from_raw_os_error(result));
        }
    }
    Ok(())
}

#[cfg(test)]
mod lock_tests {
    use super::*;
    use std::{os::windows::io::FromRawHandle, sync::mpsc, time::Instant};

    // A private name per test, so production guardians never wait on it.
    fn fixture() -> (String, String) {
        let name = format!(
            "Local\\OMD.V2.Test.ProfileLock.{}",
            uuid::Uuid::new_v4().simple()
        );
        (name, super::super::owner().unwrap())
    }
    fn code(result: Result<Held<'_>>) -> Option<i32> {
        result.err().and_then(|error| error.raw_os_error())
    }

    #[test]
    fn a_held_lock_times_out_with_a_numeric_code_and_is_then_reusable() {
        let (name, user) = fixture();
        let (held, wait_held) = mpsc::channel();
        let (release, wait_release) = mpsc::channel::<()>();
        let holder = {
            let (name, user) = (name.clone(), user.clone());
            std::thread::spawn(move || {
                let lock = ProfileLock::named(&name, &user).unwrap();
                let _held = lock.acquire_within(Duration::from_secs(5)).unwrap();
                held.send(()).unwrap();
                wait_release.recv().unwrap();
            })
        };
        wait_held.recv().unwrap();
        let lock = ProfileLock::named(&name, &user).unwrap();
        let started = Instant::now();
        assert_eq!(
            code(lock.acquire_within(Duration::from_millis(300))),
            Some(WAIT_TIMEOUT as i32)
        );
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(200) && waited < Duration::from_secs(5));
        release.send(()).unwrap();
        holder.join().unwrap();
        drop(lock.acquire_within(Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn an_abandoned_lock_passes_to_the_next_guardian() {
        let (name, user) = fixture();
        // Other guardians' handles keep the object alive after its owner dies.
        let lock = ProfileLock::named(&name, &user).unwrap();
        let abandon = |lock: &ProfileLock| {
            let (held, wait_held) = mpsc::channel();
            let (exit, wait_exit) = mpsc::channel::<()>();
            let (name, user) = (name.clone(), user.clone());
            let owner = std::thread::spawn(move || {
                let lock = ProfileLock::named(&name, &user).unwrap();
                // End while owning it, as a guardian killed mid-recovery would.
                std::mem::forget(lock.acquire_within(Duration::from_secs(5)).unwrap());
                held.send(()).unwrap();
                wait_exit.recv().unwrap();
            });
            wait_held.recv().unwrap();
            assert_eq!(
                code(lock.acquire_within(Duration::from_millis(100))),
                Some(WAIT_TIMEOUT as i32)
            );
            exit.send(()).unwrap();
            owner.join().unwrap();
        };
        // The fixture really produces an abandoned mutex.
        abandon(&lock);
        assert_eq!(
            unsafe { WaitForSingleObject(lock.0.as_raw_handle(), 5000) },
            WAIT_ABANDONED
        );
        assert_ne!(unsafe { ReleaseMutex(lock.0.as_raw_handle()) }, 0);
        // A guardian takes ownership of an abandoned lock instead of failing.
        abandon(&lock);
        let started = Instant::now();
        let held = lock
            .acquire_within(Duration::from_secs(5))
            .expect("an abandoned lock must pass to the next waiter");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held);
        drop(lock.acquire_within(Duration::from_millis(100)).unwrap());
    }

    #[test]
    fn unexpected_existing_objects_fail_closed() {
        let (name, user) = fixture();
        let event = unsafe { CreateEventW(null(), 1, 0, wide(&name).as_ptr()) };
        assert!(!event.is_null());
        let _event = unsafe { OwnedHandle::from_raw_handle(event) };
        assert_eq!(
            ProfileLock::named(&name, &user)
                .err()
                .and_then(|error| error.raw_os_error()),
            Some(ERROR_INVALID_HANDLE as i32)
        );
        // OWNER RIGHTS replaces the owner's implicit READ_CONTROL, so this
        // same-named mutex withholds the access needed to verify its owner.
        let (name, _) = fixture();
        let sd = descriptor(&format!(
            "O:{user}D:P(A;;0x00100001;;;{user})(A;;0x00100001;;;OW)"
        ))
        .unwrap();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let squatter = unsafe {
            CreateMutexExW(
                &attributes,
                wide(&name).as_ptr(),
                0,
                SYNCHRONIZATION_SYNCHRONIZE,
            )
        };
        assert!(!squatter.is_null());
        let _squatter = unsafe { OwnedHandle::from_raw_handle(squatter) };
        assert_eq!(
            ProfileLock::named(&name, &user)
                .err()
                .and_then(|error| error.raw_os_error()),
            Some(ERROR_ACCESS_DENIED as i32)
        );
    }
}
