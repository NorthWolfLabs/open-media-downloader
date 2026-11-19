//! Fixed native-adapter budgets, enforced by the unsandboxed guardian against
//! its own live process group. Interactive sign-in has a separate 2 GiB limit;
//! source extraction and other helpers retain the 1 GiB limit.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
const MAX_PROCESSES: usize = 32;
const MAX_RESIDENT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_THREADS: i64 = 1024;

pub fn start(
    group: libc::pid_t,
    interactive: bool,
) -> std::io::Result<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    // Prove that accounting is available before any helper is launched.
    let maximum = MAX_RESIDENT_BYTES * if interactive { 2 } else { 1 };
    sample(group, maximum)?;
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let thread = std::thread::Builder::new()
        .name("helper-budget".into())
        .spawn(move || {
            while !done.load(Ordering::Acquire) {
                match sample(group, maximum) {
                    Ok(true) => {}
                    result => {
                        if result.is_ok() {
                            eprintln!("OMD resource budget exceeded");
                        } else {
                            eprintln!("OMD resource accounting unavailable");
                        }
                        // The guardian is the live group leader; its identity cannot
                        // be reused while this monitor is active.
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
fn sample(group: libc::pid_t, maximum: u64) -> std::io::Result<bool> {
    let mut pids = [0i32; MAX_PROCESSES + 2]; // Include the guardian itself.
    let count = unsafe {
        libc::proc_listpids(
            2,
            group as u32,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(&pids) as i32,
        )
    };
    if count <= 0 || !(count as usize).is_multiple_of(std::mem::size_of::<i32>()) {
        return Err(std::io::Error::last_os_error());
    }
    let count = count as usize / std::mem::size_of::<i32>();
    if count >= pids.len() {
        return Ok(false);
    }
    let mut resident = 0u64;
    let mut threads = 0i64;
    for pid in &pids[..count] {
        if *pid == group || *pid == 0 {
            continue;
        }
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let bytes = unsafe {
            libc::proc_pidinfo(
                *pid,
                libc::PROC_PIDTASKINFO,
                0,
                (&mut info as *mut libc::proc_taskinfo).cast(),
                std::mem::size_of_val(&info) as i32,
            )
        };
        if bytes as usize != std::mem::size_of_val(&info) {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error);
        }
        resident = resident.saturating_add(info.pti_resident_size);
        threads = threads.saturating_add(info.pti_threadnum as i64);
    }
    Ok(resident <= maximum && threads <= MAX_THREADS && count.saturating_sub(1) <= MAX_PROCESSES)
}
