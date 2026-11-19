#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
#[cfg(target_os = "macos")]
#[path = "../macos_budget.rs"]
mod macos_budget;
// Trusted lifecycle supervisor. It runs outside the helper's sandbox and owns
// the group before launching sandbox-exec. It accepts no provider-supplied code.
#[cfg(target_os = "macos")]
fn main() {
    use std::{
        os::unix::process::{CommandExt, ExitStatusExt},
        process::{Command, Stdio},
    };
    let mut arguments = std::env::args_os().skip(1);
    let parent = arguments
        .next()
        .and_then(|s| s.to_str().and_then(|s| s.parse::<libc::pid_t>().ok()))
        .filter(|p| *p > 1)
        .unwrap_or_else(|| std::process::exit(126));
    let next = arguments.next();
    let interactive = next.as_deref() == Some(std::ffi::OsStr::new("--interactive"));
    let program = (if interactive { arguments.next() } else { next })
        .filter(|p| p == "/usr/bin/sandbox-exec")
        .unwrap_or_else(|| std::process::exit(126));
    let group = unsafe { libc::getpgrp() };
    let parent_group = unsafe { libc::getpgid(parent) };
    // Ownership must be installed by the engine; reject direct or orphan launches.
    if unsafe { libc::getppid() } != parent
        || group != unsafe { libc::getpid() }
        || parent_group <= 1
        || group == parent_group
    {
        std::process::exit(126);
    }
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        std::process::exit(126);
    }
    unsafe {
        libc::fcntl(queue, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let event = libc::kevent {
        ident: parent as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    if unsafe { libc::kevent(queue, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0
        || unsafe { libc::getppid() } != parent
    {
        std::process::exit(126);
    }
    // Register before spawn: no child can start in the parent-death race window.
    std::thread::spawn(move || {
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe {
                libc::kevent(queue, std::ptr::null(), 0, &mut event, 1, std::ptr::null())
            };
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            // Losing monitoring is fail-closed too. Group identity was established
            // by this live group leader, not inferred from a later PID lookup.
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
            std::process::exit(126);
        }
    });
    let (stop_budget, budget_monitor) =
        macos_budget::start(group, interactive).unwrap_or_else(|_| {
            eprintln!("OMD resource accounting unavailable");
            std::process::exit(126);
        });
    let mut command = Command::new(program);
    unsafe {
        command.pre_exec(|| {
            for (resource, maximum) in [(libc::RLIMIT_NOFILE, 256), (libc::RLIMIT_CORE, 0)] {
                let limit = libc::rlimit {
                    rlim_cur: maximum,
                    rlim_max: maximum,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let status = command
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    stop_budget.store(true, std::sync::atomic::Ordering::Release);
    let _ = budget_monitor.join();
    // Leave the owned group before reaping descendants on successful completion.
    // The original parent group exists while the engine is alive. If it vanished,
    // killing our original group also terminates this guardian safely.
    if unsafe { libc::setpgid(0, parent_group) } < 0 {
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        std::process::exit(126);
    }
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let code = status
        .ok()
        .map(|s| s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(1)))
        .unwrap_or(126);
    std::process::exit(code);
}
#[cfg(target_os = "linux")]
#[path = "../linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}
#[cfg(windows)]
#[path = "../windows.rs"]
mod windows;
#[cfg(windows)]
fn main() {
    match windows::main() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!(
                "OMD Windows confinement failed: {} (OS code {:?})",
                error,
                error.raw_os_error()
            );
            std::process::exit(126);
        }
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn main() {
    eprintln!("This platform's native helper guardian is unavailable.");
    std::process::exit(126);
}
