//! Windows vault entries are limited to 2,560 bytes. Two bounded banks keep the
//! current session intact until its replacement's index is atomically committed.
//! Bank manifests are written before chunks, so interrupted writes are reclaimable.
use super::{Backend, Error, Result};
use omd_domain::digest;
use zeroize::Zeroizing;

const CHUNK: usize = 2400;
const MAX: usize = 1024 * 1024;
const MAGIC: &[u8] = b"OMDVAULT1\n";

pub(super) struct Chunked<B>(pub B);
struct Index {
    bank: u8,
    len: usize,
    hash: String,
}
fn index(bytes: &[u8]) -> Result<Option<Index>> {
    if !bytes.starts_with(MAGIC) {
        return Ok(None);
    }
    let data = &bytes[MAGIC.len()..];
    if data.len() != 69 || data[0] > 1 {
        return Err(Error::Invalid);
    }
    let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
    let hash = std::str::from_utf8(&data[5..])
        .map_err(|_| Error::Invalid)?
        .to_owned();
    if len == 0 || len > MAX || !hash.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err(Error::Invalid);
    }
    Ok(Some(Index {
        bank: data[0],
        len,
        hash,
    }))
}
fn bank_key(key: &str, bank: u8) -> String {
    format!("{key}.bank{bank}")
}
impl<B: Backend> Chunked<B> {
    fn count(&self, key: &str) -> Result<usize> {
        match self.0.read(key) {
            Err(Error::Missing) => Ok(0),
            Err(e) => Err(e),
            Ok(bytes) => {
                let count =
                    u32::from_le_bytes(bytes.as_slice().try_into().map_err(|_| Error::Invalid)?)
                        as usize;
                if count > MAX.div_ceil(CHUNK) {
                    return Err(Error::Invalid);
                }
                Ok(count)
            }
        }
    }
    fn clean(&self, key: &str, bank: u8) -> Result<()> {
        let key = bank_key(key, bank);
        for n in 0..self.count(&key)? {
            self.0.remove(&format!("{key}.{n}"))?;
        }
        self.0.remove(&key)
    }
}
impl<B: Backend> Backend for Chunked<B> {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let root = self.0.read(key)?;
        let Some(index) = index(&root)? else {
            return Ok(root);
        };
        let bank = bank_key(key, index.bank);
        let count = index.len.div_ceil(CHUNK);
        if self.count(&bank)? != count {
            return Err(Error::Invalid);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(index.len));
        for n in 0..count {
            let chunk = self.0.read(&format!("{bank}.{n}"))?;
            if chunk.len() != (index.len - n * CHUNK).min(CHUNK) {
                return Err(Error::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        if digest(&bytes) != index.hash {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
    fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX {
            return Err(Error::Invalid);
        }
        let active = match self.0.read(key) {
            Ok(value) => index(&value)?.map(|x| x.bank),
            Err(Error::Missing) => None,
            Err(e) => return Err(e),
        };
        let bank = active.map_or(0, |x| 1 - x);
        self.clean(key, bank)?;
        let name = bank_key(key, bank);
        let count = bytes.len().div_ceil(CHUNK);
        self.0.write(&name, &(count as u32).to_le_bytes())?;
        for (n, chunk) in bytes.chunks(CHUNK).enumerate() {
            self.0.write(&format!("{name}.{n}"), chunk)?;
        }
        let mut root = MAGIC.to_vec();
        root.push(bank);
        root.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        root.extend_from_slice(digest(bytes).as_bytes());
        self.0.write(key, &root)?;
        // Publication succeeded. Cleanup failure cannot report a failed save;
        // the next mutation retries cleanup using the retained bank manifest.
        let _ = self.clean(key, 1 - bank);
        Ok(())
    }
    fn remove(&self, key: &str) -> Result<()> {
        self.0.remove(key)?;
        self.clean(key, 0)?;
        self.clean(key, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};
    type MemoryState = (BTreeMap<String, Vec<u8>>, Option<usize>);
    #[derive(Default)]
    struct Memory(Mutex<MemoryState>);
    impl Memory {
        fn mutate(&self, f: impl FnOnce(&mut BTreeMap<String, Vec<u8>>)) -> Result<()> {
            let mut state = self.0.lock().unwrap();
            if let Some(left) = &mut state.1 {
                if *left == 0 {
                    return Err(Error::Unavailable);
                }
                *left -= 1;
            }
            f(&mut state.0);
            Ok(())
        }
    }
    impl Backend for Memory {
        fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
            self.0
                .lock()
                .unwrap()
                .0
                .get(key)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(Error::Missing)
        }
        fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
            assert!(bytes.len() <= 2560);
            self.mutate(|map| {
                map.insert(key.into(), bytes.to_vec());
            })
        }
        fn remove(&self, key: &str) -> Result<()> {
            self.mutate(|map| {
                map.remove(key);
            })
        }
    }
    #[test]
    fn every_interrupted_replace_and_revoke_is_recoverable() {
        let old = vec![1; 7000];
        let new = vec![2; 11000];
        for stop in 0..25 {
            let vault = Chunked(Memory::default());
            vault.write("session", &old).unwrap();
            vault.0.0.lock().unwrap().1 = Some(stop);
            let result = vault.write("session", &new);
            let read = vault.read("session").unwrap();
            assert!(read.as_slice() == old || read.as_slice() == new);
            if result.is_ok() {
                assert_eq!(read.as_slice(), new);
            }
            vault.0.0.lock().unwrap().1 = None;
            vault.write("session", &new).unwrap();
            assert_eq!(*vault.read("session").unwrap(), new);
            vault.0.0.lock().unwrap().1 = Some(stop);
            let _ = vault.remove("session");
            vault.0.0.lock().unwrap().1 = None;
            vault.remove("session").unwrap();
            assert!(vault.0.0.lock().unwrap().0.is_empty());
        }
    }
    #[test]
    fn maximum_size_and_corruption_are_checked() {
        let vault = Chunked(Memory::default());
        let bytes = vec![7; MAX];
        vault.write("session", &bytes).unwrap();
        assert_eq!(*vault.read("session").unwrap(), bytes);
        vault.0.write("session.bank0.0", &vec![8; CHUNK]).unwrap();
        assert_eq!(vault.read("session").unwrap_err(), Error::Invalid);
        assert_eq!(
            vault.write("session", &vec![0; MAX + 1]),
            Err(Error::Invalid)
        );
        vault.remove("session").unwrap();
        assert!(vault.0.0.lock().unwrap().0.is_empty());
    }
    #[test]
    fn existing_v2_sessions_survive_interrupted_conversion() {
        let vault = Chunked(Memory::default());
        vault.0.write("session", b"{\"cookies\":[]}").unwrap();
        vault.0.0.lock().unwrap().1 = Some(3);
        assert!(vault.write("session", &vec![9; 12000]).is_err());
        assert_eq!(
            vault.read("session").unwrap().as_slice(),
            b"{\"cookies\":[]}"
        );
        vault.0.0.lock().unwrap().1 = None;
        vault.remove("session").unwrap();
        assert!(vault.0.0.lock().unwrap().0.is_empty());
    }
}
