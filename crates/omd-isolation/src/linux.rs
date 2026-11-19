//! Linux guardian. Trusted relays bridge one fixed broker port into a fresh
//! network namespace. Helpers inherit Landlock and seccomp, never a host socket.
//! PID-namespace init owns every descendant; its death kills the entire tree.
#[path = "linux_budget.rs"]
mod browser_budget;
use omd_isolation::Policy;
use std::{
    ffi::CString,
    io,
    net::{TcpListener, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

type Result<T> = io::Result<T>;
fn checked(value: libc::c_long) -> Result<libc::c_long> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
fn death(parent: libc::pid_t) -> Result<()> {
    checked(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } as _)?;
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::other("owner departed"));
    }
    Ok(())
}
fn wait(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            break;
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return 126;
        }
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    }
}
pub fn main() {
    if let Err(error) = launch() {
        // No provider payload, paths, cookies, or command arguments in diagnostics.
        eprintln!(
            "OMD confinement unavailable: {} ({:?}). Enable unprivileged user namespaces, Landlock ABI 3+, and seccomp.",
            error.kind(),
            error.raw_os_error()
        );
        std::process::exit(126);
    }
}
fn launch() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let parent: i32 = args
        .next()
        .and_then(|s| s.to_str().and_then(|s| s.parse().ok()))
        .filter(|p| *p > 1)
        .ok_or_else(|| io::Error::other("owner"))?;
    let browser = match args.next().and_then(|s| s.into_string().ok()).as_deref() {
        Some("browser") => true,
        Some("media") => false,
        _ => return Err(io::Error::other("adapter mode")),
    };
    let policy: Policy = serde_json::from_str(
        &args
            .next()
            .and_then(|s| s.into_string().ok())
            .filter(|s| s.len() < 65536)
            .ok_or_else(|| io::Error::other("policy"))?,
    )?;
    let args: Vec<_> = args.collect();
    if unsafe { libc::getpgrp() } != unsafe { libc::getpid() } {
        return Err(io::Error::other("group"));
    }
    death(parent)?;
    if browser {
        browser_budget::probe(unsafe { libc::getpid() })?;
    }
    // OwnedFd validates the required ABI before any child can execute.
    let rules = filesystem(&policy, false)?;
    let filters = filter();
    // A private socketpair carries accepted connections via SCM_RIGHTS. It is
    // never inherited by a helper. Unlike a pathname socket, it leaves no crash
    // debris or discoverable endpoint in the user's filesystem.
    let (host, guest) = UnixStream::pair()?;
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let owner = unsafe { libc::getpid() };
    // The guardian has no threads at either fork boundary.
    let child = checked(unsafe { libc::fork() } as _)? as i32;
    if child == 0 {
        drop(host);
        let mut stage = "owner";
        let result = (|| -> Result<()> {
            death(owner)?;
            stage = "user namespace";
            checked(unsafe { libc::unshare(libc::CLONE_NEWUSER) } as _)?;
            stage = "group mapping";
            std::fs::write("/proc/self/setgroups", "deny")?;
            stage = "user mapping";
            std::fs::write("/proc/self/uid_map", format!("65534 {uid} 1\n"))?;
            stage = "group ID mapping";
            std::fs::write("/proc/self/gid_map", format!("65534 {gid} 1\n"))?;
            stage = "network/PID namespaces";
            checked(unsafe {
                libc::unshare(
                    libc::CLONE_NEWNET
                        | libc::CLONE_NEWIPC
                        | libc::CLONE_NEWUTS
                        | libc::CLONE_NEWPID
                        | libc::CLONE_NEWNS,
                )
            } as _)?;
            stage = "read-only filesystem";
            readonly_mounts(&policy.work)?;
            // The inherited cwd references the old, now read-only mount. Resolve
            // it again through the namespace's new writable staging mount.
            std::env::set_current_dir(&policy.work)?;
            stage = "loopback";
            loopback()?;
            let creator = unsafe { libc::getpid() };
            let owner_fd = checked(unsafe { libc::syscall(libc::SYS_pidfd_open, creator, 0) })?;
            let owner_fd = unsafe { OwnedFd::from_raw_fd(owner_fd as i32) };
            let init = checked(unsafe { libc::fork() } as _)? as i32;
            if init != 0 {
                std::process::exit(wait(init));
            }
            // Parent is outside this PID namespace and appears as PID 0. Verify
            // lifetime using the socket as well; creator has PDEATHSIG installed.
            death(0)?;
            let rules = if browser {
                // The browser may inspect only its own PID namespace. Never
                // grant it the inherited host /proc view or guardian descriptors.
                stage = "private browser proc";
                checked(unsafe {
                    libc::mount(
                        c"proc".as_ptr(),
                        c"/proc".as_ptr(),
                        c"proc".as_ptr(),
                        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                        c"hidepid=2".as_ptr().cast(),
                    )
                } as _)?;
                checked(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } as _)?;
                stage = "private browser hardware view";
                private_hardware_view()?;
                drop(rules);
                filesystem(&policy, true)?
            } else {
                rules
            };
            std::thread::spawn(move || {
                let mut item = libc::pollfd {
                    fd: owner_fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                loop {
                    let result = unsafe { libc::poll(&mut item, 1, -1) };
                    if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    std::process::exit(126);
                }
            });
            stage = "helper policy";
            inner(policy, args, guest, rules, filters, browser)
        })();
        if let Err(error) = result {
            eprintln!(
                "OMD namespace confinement unavailable at {stage} ({:?})",
                error.raw_os_error()
            );
        }
        std::process::exit(126);
    }
    drop(guest);
    drop(rules);
    let budget = if browser {
        Some(browser_budget::start(owner)?)
    } else {
        None
    };
    if let Some(port) = policy.broker_port {
        std::thread::spawn(move || host_relay(host, port));
    } else {
        drop(host);
    }
    let status = wait(child);
    if let Some((stop, thread)) = budget {
        stop.store(true, Ordering::Release);
        let _ = thread.join();
    }
    std::process::exit(status);
}

fn private_hardware_view() -> Result<()> {
    // libpci exits the Chromium GPU process when its directory cannot be opened,
    // even for software rendering. Supply an empty private inventory instead of
    // granting access to real device topology, identifiers or driver interfaces.
    checked(unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            c"/sys".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"size=64k,nr_inodes=16,mode=0755,uid=65534,gid=65534"
                .as_ptr()
                .cast(),
        )
    } as _)?;
    std::fs::create_dir_all("/sys/bus/pci/devices")?;
    checked(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/sys".as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } as _)?;
    Ok(())
}

fn loopback() -> Result<()> {
    let fd =
        checked(
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) } as _,
        )?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as _;
    request.ifr_name[1] = b'o' as _;
    checked(unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request) } as _)?;
    unsafe {
        request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    }
    checked(unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) } as _)?;
    Ok(())
}

fn readonly_mounts(work: &Path) -> Result<()> {
    let root = c"/";
    let work = CString::new(work.as_os_str().as_bytes())?;
    // Propagation changes apply only to this newly unshared mount namespace.
    checked(unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } as _)?;
    // Create an owned bind before making inherited mounts read-only. Only this
    // work mount can subsequently regain write access. Landlock separately
    // denies reading the rest of the filesystem and executing staged files.
    checked(unsafe {
        libc::mount(
            work.as_ptr(),
            work.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } as _)?;
    #[repr(C)]
    struct Attributes {
        set: u64,
        clear: u64,
        propagation: u64,
        userns: u64,
    }
    let readonly = Attributes {
        set: 1 | 2,
        clear: 0,
        propagation: 0,
        userns: 0,
    };
    checked(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            root.as_ptr(),
            0x8000u32,
            &readonly,
            std::mem::size_of_val(&readonly),
        )
    })?;
    let writable = Attributes {
        set: 2,
        clear: 1,
        propagation: 0,
        userns: 0,
    };
    checked(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            work.as_ptr(),
            0u32,
            &writable,
            std::mem::size_of_val(&writable),
        )
    })?;
    Ok(())
}

// Send/receive only connected TCP sockets, over a private trusted socketpair.
// SOCK_STREAM ancillary data is accompanied by one byte, with one FD per call.
fn send_fd(socket: &UnixStream, fd: i32) -> Result<()> {
    let mut byte = [1u8];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd);
        checked(libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) as _)?;
    }
    Ok(())
}
fn receive_fd(socket: &UnixStream) -> Result<TcpStream> {
    let mut byte = [0u8];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    unsafe {
        if checked(libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) as _)?
            != 1
        {
            return Err(io::Error::other("relay closed"));
        }
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
            || (*header).cmsg_len as usize != libc::CMSG_LEN(4) as usize
            || message.msg_flags & libc::MSG_CTRUNC != 0
        {
            return Err(io::Error::other("relay protocol"));
        }
        Ok(TcpStream::from_raw_fd(std::ptr::read_unaligned(
            libc::CMSG_DATA(header).cast::<i32>(),
        )))
    }
}
fn host_relay(socket: UnixStream, port: u16) {
    let active = Arc::new(AtomicUsize::new(0));
    while let Ok(mut guest) = receive_fd(&socket) {
        if active.load(Ordering::Acquire) >= 32 {
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let active = active.clone();
        std::thread::spawn(move || {
            if let Ok(mut broker) =
                TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(3))
            {
                // Idle connections cannot exhaust relay capacity indefinitely.
                let _ = guest.set_read_timeout(Some(Duration::from_secs(120)));
                let _ = guest.set_write_timeout(Some(Duration::from_secs(120)));
                let _ = broker.set_read_timeout(Some(Duration::from_secs(120)));
                let _ = broker.set_write_timeout(Some(Duration::from_secs(120)));
                if let (Ok(mut guest_out), Ok(mut broker_in)) =
                    (guest.try_clone(), broker.try_clone())
                {
                    let thread = std::thread::spawn(move || {
                        let _ = io::copy(&mut broker_in, &mut guest_out);
                        let _ = guest_out.shutdown(std::net::Shutdown::Write);
                    });
                    let _ = io::copy(&mut guest, &mut broker);
                    let _ = broker.shutdown(std::net::Shutdown::Write);
                    let _ = thread.join();
                }
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
}
fn inner(
    policy: Policy,
    args: Vec<std::ffi::OsString>,
    relay: UnixStream,
    rules: OwnedFd,
    filters: Vec<libc::sock_filter>,
    browser: bool,
) -> Result<()> {
    if let Some(port) = policy.broker_port {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
        std::thread::spawn(move || {
            for connection in listener.incoming() {
                let Ok(connection) = connection else {
                    std::process::exit(126)
                };
                if send_fd(&relay, connection.as_raw_fd()).is_err() {
                    std::process::exit(126);
                }
            }
        });
    } else {
        drop(relay);
    }
    let mut command = Command::new(&policy.executable);
    command
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(move || {
            // Only async-signal-safe syscalls here, after Command's fork.
            for (resource, maximum) in [
                (libc::RLIMIT_NPROC, if browser { 1024u64 } else { 64 }),
                (libc::RLIMIT_NOFILE, 256),
                (
                    libc::RLIMIT_AS,
                    if browser {
                        2 * 1024_u64.pow(4)
                    } else {
                        16 * 1024_u64.pow(3)
                    },
                ),
                (libc::RLIMIT_CORE, 0),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: maximum as _,
                    rlim_max: maximum as _,
                };
                enforce(
                    libc::setrlimit(resource, &limit) as _,
                    b"OMD resource confinement failed\n",
                )?;
            }
            enforce(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as _,
                b"OMD no-new-privileges failed\n",
            )?;
            enforce(
                libc::syscall(libc::SYS_landlock_restrict_self, rules.as_raw_fd(), 0),
                b"OMD Landlock enforcement failed\n",
            )?;
            // Drop all inherited privilege in the new user namespace as well.
            for capability in 0..=40 {
                enforce(
                    libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) as _,
                    b"OMD capability bounding failed\n",
                )?;
            }
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            struct Cap {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let caps = [
                Cap {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
                Cap {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            enforce(
                libc::syscall(libc::SYS_capset, &header, caps.as_ptr()),
                b"OMD capability removal failed\n",
            )?;
            checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) as _)?;
            let program = libc::sock_fprog {
                len: filters.len() as u16,
                filter: filters.as_ptr() as *mut _,
            };
            enforce(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) as _,
                b"OMD seccomp enforcement failed\n",
            )?;
            // All guardian sockets/ruleset FDs are CLOEXEC. Mark every remaining
            // FD too, preserving Command's error pipe until exec succeeds/fails.
            enforce(
                libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32),
                b"OMD descriptor confinement failed\n",
            )?;
            Ok(())
        });
    }
    let status = command.status()?;
    // Exiting namespace init kills even double-forked or session-detached children.
    std::process::exit(status.code().unwrap_or(126));
}

fn filesystem(policy: &Policy, browser: bool) -> Result<OwnedFd> {
    // ABI 3 adds truncate protection; never silently drop required rights.
    let abi = checked(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    })?;
    if abi < 3 {
        return Err(io::Error::other("Landlock ABI"));
    }
    const ALL: u64 = (1 << 15) - 1;
    const READ: u64 = (1 << 2) | (1 << 3);
    const WRITE: u64 =
        (1 << 1) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 8) | (1 << 12) | (1 << 13) | (1 << 14);
    let fd = checked(unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &ALL, 8, 0) })?;
    let rules = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let add = |path: &Path, mut rights: u64| -> Result<()> {
        if !path.is_dir() {
            rights &= 1 | (1 << 1) | (1 << 2) | (1 << 14);
        }
        let name = CString::new(path.as_os_str().as_bytes())?;
        let fd =
            checked(unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) } as _)?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        #[repr(C, packed)]
        struct Beneath {
            rights: u64,
            fd: i32,
        }
        let attr = Beneath {
            rights,
            fd: fd.as_raw_fd(),
        };
        checked(unsafe {
            libc::syscall(libc::SYS_landlock_add_rule, rules.as_raw_fd(), 1, &attr, 0)
        })?;
        Ok(())
    };
    for path in [
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/dev/urandom",
        "/dev/random",
    ] {
        if Path::new(path).exists() {
            add(Path::new(path), READ)?;
        }
    }
    if browser {
        for path in [
            "/proc",
            "/usr/share/fonts",
            "/usr/share/fontconfig",
            "/etc/fonts",
            "/var/cache/fontconfig",
            "/sys/bus/pci/devices",
        ] {
            if Path::new(path).exists() {
                add(Path::new(path), READ)?;
            }
        }
    }
    // The kernel separately checks an ELF interpreter's execute permission.
    for path in ["/lib/ld-linux-aarch64.so.1", "/lib64/ld-linux-x86-64.so.2"] {
        if Path::new(path).exists() {
            add(Path::new(path), READ | 1)?;
        }
    }
    add(Path::new("/dev/null"), READ | (1 << 1))?;
    for path in &policy.readable {
        add(path, READ)?;
    }
    add(&policy.work, READ | WRITE)?;
    for path in std::iter::once(&policy.executable).chain(policy.executables.iter()) {
        add(path, READ | 1)?;
    }
    Ok(rules)
}

fn filter() -> Vec<libc::sock_filter> {
    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut result = vec![
        stmt(0x20, 4),
        jump(ARCH, 1, 0),
        stmt(0x06, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(0x20, 0),
    ];
    // The x32 ABI shares AUDIT_ARCH_X86_64 but uses a different syscall table.
    result.extend([
        stmt(0x54, 0x40000000),
        jump(0, 1, 0),
        stmt(0x06, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(0x20, 0),
    ]);
    result.extend([
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 451,
        },
        stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
    ]);
    for call in [
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_setsid,
        libc::SYS_setpgid,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_bpf,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_mount_setattr,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
    ] {
        result.extend([jump(call as u32, 0, 1), stmt(0x06, deny)]);
    }
    // clone3 has pointer arguments; force libc to use inspectable clone instead.
    result.extend([
        jump(libc::SYS_clone3 as u32, 0, 1),
        stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
    ]);
    result.extend([
        jump(libc::SYS_clone as u32, 0, 4),
        stmt(0x20, 16),
        stmt(0x54, 0x7e020080),
        jump(0, 1, 0),
        stmt(0x06, deny),
        stmt(0x20, 0),
    ]);
    // Only harmless descriptor queries. Filesystem mutation ioctls are not
    // covered by Landlock ABI 3 and must not become a metadata-write bypass.
    result.extend([
        jump(libc::SYS_ioctl as u32, 0, 4),
        stmt(0x20, 24),
        jump(0x541b, 2, 0),
        jump(0x5421, 1, 0),
        stmt(0x06, deny),
        stmt(0x20, 0),
    ]);
    // AF_UNIX pathname sockets ignore network namespaces: deny their creation.
    // socketpair is still available for a helper's own internal communication.
    result.extend([
        jump(libc::SYS_socket as u32, 0, 8),
        stmt(0x20, 16),
        jump(libc::AF_INET as u32, 2, 0),
        jump(libc::AF_INET6 as u32, 1, 0),
        stmt(0x06, deny),
        stmt(0x20, 24),
        stmt(0x54, 15),
        jump(libc::SOCK_STREAM as u32, 1, 0),
        stmt(0x06, deny),
        stmt(0x06, libc::SECCOMP_RET_ALLOW),
    ]);
    result
}

fn enforce(value: libc::c_long, label: &[u8]) -> Result<()> {
    if value < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::write(2, label.as_ptr().cast(), label.len());
        }
        Err(error)
    } else {
        Ok(())
    }
}
