//! Installer entry point: stop only this profile's authenticated engine and wait
//! for its ownership lock. Never kill a process or change user preferences.
use anyhow::{Context, ensure};
use serde::Deserialize;
use std::{fs::OpenOptions, path::Path, time::Duration};

#[derive(Deserialize)]
struct Instance {
    endpoint: String,
    admin_token: String,
    pid: u32,
}

/// Called by the authenticated owner before shutdown. Waiting startup engines
/// exit on this marker instead of racing the replacement for the profile lock.
pub async fn suspend(profile: &Path) -> anyhow::Result<()> {
    let marker = profile.join("update.pending");
    let created = match omd_files::create_private_file(&marker) {
        Ok(file) => {
            file.sync_all()?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                std::fs::symlink_metadata(&marker)?.file_type().is_file(),
                "Invalid update marker"
            );
            false
        }
        Err(error) => return Err(error.into()),
    };
    if let Err(error) = omd_lifecycle::suspend_registration(profile).await {
        if created {
            let _ = std::fs::remove_file(marker);
        }
        return Err(error.into());
    }
    Ok(())
}

pub async fn prepare(profile: &Path) -> anyhow::Result<()> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(profile.join("engine.lock"))?;
    match fs2::FileExt::try_lock_exclusive(&lock) {
        Ok(()) => {
            omd_lifecycle::suspend_registration(profile).await?;
            return Ok(());
        }
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {}
        Err(error) => return Err(error.into()),
    }
    let path = profile.join("instance.json");
    ensure!(
        std::fs::symlink_metadata(&path)?.file_type().is_file(),
        "Invalid engine authority file"
    );
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::open(path)?, 65537),
        &mut data,
    )?;
    ensure!(data.len() <= 65536, "Invalid engine authority file");
    let instance: Instance =
        serde_json::from_slice(&data).context("Invalid engine authority file")?;
    validate_endpoint(&instance.endpoint)?;
    ensure!(
        !instance.admin_token.is_empty() && instance.admin_token.len() <= 256,
        "Invalid engine authority"
    );
    ensure!(
        instance.pid != 0 && instance.pid != std::process::id(),
        "Invalid engine process identity"
    );
    #[cfg(windows)]
    let process = Process::open(instance.pid)?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    http.post(format!("{}/v2/service/shutdown", instance.endpoint))
        .query(&[("for_update", "true")])
        .bearer_auth(&instance.admin_token)
        .send()
        .await
        .context("The engine could not be stopped. Quit OMD and retry the installer.")?
        .error_for_status()
        .context("The engine refused shutdown. Quit OMD and retry the installer.")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        match fs2::FileExt::try_lock_exclusive(&lock) {
            Ok(()) => break,
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "The engine is still stopping. Retry the installer after OMD exits."
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Windows must release the mapped executable before the installer replaces
    // it. Hold the same process handle across shutdown to avoid PID-reuse races.
    #[cfg(windows)]
    process.wait(deadline).await?;
    // Unix permits replacing a running image, but let the engine's bounded
    // five-second blocking-runtime grace finish before declaring it quiescent.
    #[cfg(not(windows))]
    tokio::time::sleep(Duration::from_secs(6)).await;
    Ok(())
}

pub fn validate_endpoint(endpoint: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(endpoint)?;
    ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid local engine endpoint"
    );
    Ok(())
}

#[cfg(windows)]
struct Process(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Process {
    fn open(pid: u32) -> anyhow::Result<Self> {
        let handle =
            unsafe { windows_sys::Win32::System::Threading::OpenProcess(0x0010_0000, 0, pid) };
        ensure!(
            !handle.is_null(),
            "Could not observe engine exit. Quit OMD and retry the installer."
        );
        Ok(Self(handle))
    }
    async fn wait(&self, deadline: tokio::time::Instant) -> anyhow::Result<()> {
        loop {
            let result =
                unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(self.0, 0) };
            if result == 0 {
                return Ok(());
            }
            ensure!(
                result == 258 && tokio::time::Instant::now() < deadline,
                "The engine has not exited. Retry the installer after OMD exits."
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}
#[cfg(windows)]
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shutdown_cannot_forward_authority_off_loopback_or_through_url_components() {
        assert!(validate_endpoint("http://127.0.0.1:1234").is_ok());
        for url in [
            "https://127.0.0.1:1234",
            "http://localhost:1234",
            "http://example.org:1234",
            "http://user@127.0.0.1:1234",
            "http://127.0.0.1:1234/path",
            "http://127.0.0.1:1234?next=x",
            "http://127.0.0.1:1234#x",
        ] {
            assert!(validate_endpoint(url).is_err(), "{url}");
        }
    }
    #[tokio::test]
    async fn an_idle_profile_requires_no_network_and_keeps_user_files() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("settings.json"), b"preserve").unwrap();
        prepare(folder.path()).await.unwrap();
        assert_eq!(
            std::fs::read(folder.path().join("settings.json")).unwrap(),
            b"preserve"
        );
    }
}
