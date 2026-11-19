//! Sample resident memory for the guardian's own live, immutable process group.
//! Virtual address reservations are not memory consumption (Chromium reserves
//! large PROT_NONE arenas). The kernel still enforces address/task/FD limits.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
const MAX_PROCESSES: usize = 32;
const MAX_RESIDENT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_THREADS: u64 = 1024;

pub fn probe(group: i32) -> std::io::Result<()> {
    if sample(group)? {
        Ok(())
    } else {
        Err(std::io::Error::other("resource budget"))
    }
}
pub fn start(group: i32) -> std::io::Result<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    probe(group)?;
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let thread = std::thread::Builder::new()
        .name("omd-browser-budget".into())
        .spawn(move || {
            while !done.load(Ordering::Acquire) {
                match sample(group) {
                    Ok(true) => {}
                    value => {
                        eprintln!(
                            "{}",
                            if value.is_err() {
                                "OMD resource accounting unavailable"
                            } else {
                                "OMD resource budget exceeded"
                            }
                        );
                        // The group leader is this live guardian; helpers cannot
                        // change groups or signal the guardian under seccomp.
                        unsafe {
                            libc::kill(-group, libc::SIGKILL);
                        }
                        std::process::exit(126);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })?;
    Ok((stop, thread))
}
fn sample(group: i32) -> std::io::Result<bool> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return Err(std::io::Error::other("page accounting"));
    }
    let mut found = false;
    let mut processes = 0;
    let mut resident = 0u64;
    let mut threads = 0u64;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => continue,
            Err(e) => return Err(e),
        };
        let fields = stat
            .rsplit_once(')')
            .ok_or_else(|| std::io::Error::other("process accounting"))?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        let pgrp = fields
            .get(2)
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or_else(|| std::io::Error::other("group accounting"))?;
        if pgrp != group {
            continue;
        }
        found = true;
        let number = |index: usize| {
            fields
                .get(index)
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| std::io::Error::other("memory accounting"))
        };
        resident = resident.saturating_add(number(21)?.saturating_mul(page as u64));
        threads = threads.saturating_add(number(17)?);
        processes += 1;
        // Include the three trusted guardian processes and their relay threads.
        if processes > MAX_PROCESSES + 3 || resident > MAX_RESIDENT_BYTES || threads > MAX_THREADS {
            return Ok(false);
        }
    }
    if !found {
        return Err(std::io::Error::other("group accounting unavailable"));
    }
    Ok(true)
}
