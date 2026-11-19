//! Noninteractive Secret Service access for background acquisition. The generic
//! keyring backend automatically unlocks matching items, potentially waiting on
//! an invisible desktop prompt. Report locked state instead; the user unlocks
//! their store through its OS interface and retries the same account identity.
use super::{Backend, Error, Native, Result};
use secret_service::{
    EncryptionType,
    blocking::{Item, SecretService},
};
use std::collections::HashMap;
use zeroize::Zeroizing;

const SERVICE: &str = "org.northwolf.omd.v2";

fn failure(error: secret_service::Error) -> Error {
    match error {
        secret_service::Error::Locked | secret_service::Error::Prompt => Error::Locked,
        // A collection can lock between SearchItems and GetSecret/SetSecret.
        secret_service::Error::Zbus(zbus_error) => {
            if matches!(&zbus_error, zbus::Error::MethodError(name, _, _)
                if name.as_str() == "org.freedesktop.Secret.Error.IsLocked")
            {
                Error::Locked
            } else {
                Error::Unavailable
            }
        }
        _ => Error::Unavailable,
    }
}

fn connect() -> Result<SecretService<'static>> {
    // Retain encrypted session transport; secrets do not travel as plain D-Bus
    // arguments even though the bus itself belongs to this user.
    SecretService::connect(EncryptionType::Dh).map_err(failure)
}

fn attributes(key: &str) -> HashMap<&str, &str> {
    // Match existing v2 keyring-created entries without searching other apps or
    // silently adopting entries from unrelated collections/legacy databases.
    HashMap::from([
        ("service", SERVICE),
        ("username", key),
        ("target", "default"),
    ])
}

fn find<'a>(service: &'a SecretService<'_>, key: &str) -> Result<Option<Item<'a>>> {
    let mut items = service.search_items(attributes(key)).map_err(failure)?;
    if !items.locked.is_empty() {
        return Err(Error::Locked);
    }
    if items.unlocked.len() > 1 {
        return Err(Error::Unavailable);
    }
    Ok(items.unlocked.pop())
}

impl Backend for Native {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let service = connect()?;
        let item = find(&service, key)?.ok_or(Error::Missing)?;
        item.ensure_unlocked().map_err(failure)?;
        item.get_secret().map(Zeroizing::new).map_err(failure)
    }

    fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let service = connect()?;
        if let Some(item) = find(&service, key)? {
            item.ensure_unlocked().map_err(failure)?;
            return item
                .set_secret(bytes, "application/octet-stream")
                .map_err(failure);
        }
        let collection = service.get_default_collection().map_err(failure)?;
        if collection.is_locked().map_err(failure)? {
            return Err(Error::Locked);
        }
        let mut attributes = attributes(key);
        attributes.insert("application", "org.northwolf.omd.v2");
        collection
            .create_item(
                "OMD source account",
                attributes,
                bytes,
                true,
                "application/octet-stream",
            )
            .map_err(failure)?;
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        let service = connect()?;
        if let Some(item) = find(&service, key)? {
            item.ensure_unlocked().map_err(failure)?;
            item.delete().map_err(failure)?;
        }
        Ok(())
    }
}
