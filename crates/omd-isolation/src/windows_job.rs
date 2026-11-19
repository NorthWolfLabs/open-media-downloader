//! Engine-owned Windows process lifetime. The engine keeps a query handle so
//! cancellation can wait for the entire native job before releasing staging.
use std::{
    io,
    mem::size_of_val,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{JobObjects::*, SystemServices::*},
};
fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain([0])
        .collect()
}
fn check(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub struct Job {
    handle: OwnedHandle,
    #[allow(dead_code)] // The engine exports this identity; the guardian only adopts it.
    pub name: String,
}
impl AsRawHandle for Job {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.handle.as_raw_handle()
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        self.terminate();
    }
}
impl Job {
    pub fn create() -> io::Result<Self> {
        let name = format!("Local\\OMD.V2.Native.Job.{}", uuid::Uuid::new_v4().simple());
        let raw = unsafe { CreateJobObjectW(null(), wide(&name).as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Err(io::Error::other("Native job identity collision"));
        }
        let value = Self { handle, name };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.BasicLimitInformation.ActiveProcessLimit = 64;
        limits.JobMemoryLimit = 2 * 1024 * 1024 * 1024;
        check(unsafe {
            SetInformationJobObject(
                value.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
            )
        })?;
        let cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 { CpuRate: 5000 },
        };
        check(unsafe {
            SetInformationJobObject(
                value.as_raw_handle(),
                JobObjectCpuRateControlInformation,
                (&cpu as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
                size_of_val(&cpu) as u32,
            )
        })?;
        Ok(value)
    }
    #[allow(dead_code)] // Shared source compiled into both the engine and guardian.
    pub fn guardian() -> io::Result<Self> {
        let Some(name) = std::env::var_os("OMD_SUPERVISOR_JOB") else {
            return Self::create();
        };
        let name = name
            .into_string()
            .map_err(|_| io::Error::other("Invalid job identity"))?;
        let nonce = name
            .strip_prefix("Local\\OMD.V2.Native.Job.")
            .ok_or_else(|| io::Error::other("Invalid job identity"))?;
        if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::other("Invalid job identity"));
        }
        let raw = unsafe {
            OpenJobObjectW(
                JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE,
                0,
                wide(&name).as_ptr(),
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw) },
            name,
        })
    }
    pub fn terminate(&self) {
        unsafe {
            TerminateJobObject(self.as_raw_handle(), 126);
        }
    }
    pub async fn drain(&self) -> io::Result<()> {
        self.terminate();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut count: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                    unsafe { std::mem::zeroed() };
                check(unsafe {
                    QueryInformationJobObject(
                        self.as_raw_handle(),
                        JobObjectBasicAccountingInformation,
                        (&mut count as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of_val(&count) as u32,
                        null_mut(),
                    )
                })?;
                if count.ActiveProcesses == 0 {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| io::Error::other("Native process cleanup deadline exceeded"))?
    }
}
