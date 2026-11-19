//! Identity of the running image, captured before its on-disk file can be replaced.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, sync::OnceLock};

#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub api: String,
    pub version: String,
    pub executable_sha256: String,
}

pub fn current() -> std::io::Result<&'static Identity> {
    static IDENTITY: OnceLock<Identity> = OnceLock::new();
    if let Some(identity) = IDENTITY.get() {
        return Ok(identity);
    }
    let mut input = std::fs::File::open(std::env::current_exe()?)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
    }
    let _ = IDENTITY.set(Identity {
        api: "v2".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        executable_sha256: format!("{:x}", digest.finalize()),
    });
    Ok(IDENTITY.get().expect("identity initialized"))
}
