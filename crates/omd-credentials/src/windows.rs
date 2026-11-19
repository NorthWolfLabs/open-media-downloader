use super::{Backend, Error, Native, NativeEntry, Result, chunked::Chunked};
use std::sync::Mutex;
use zeroize::Zeroizing;

// One engine owns a profile. Blocking vault calls within that engine must not
// interleave bank replacement with reads or revocation of the same session.
static ACCESS: Mutex<()> = Mutex::new(());
impl Backend for Native {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let _guard = ACCESS.lock().map_err(|_| Error::Unavailable)?;
        Chunked(NativeEntry).read(key)
    }
    fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let _guard = ACCESS.lock().map_err(|_| Error::Unavailable)?;
        Chunked(NativeEntry).write(key, bytes)
    }
    fn remove(&self, key: &str) -> Result<()> {
        let _guard = ACCESS.lock().map_err(|_| Error::Unavailable)?;
        Chunked(NativeEntry).remove(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires an interactive Windows credential store; writes only a unique fixture entry"]
    fn native_large_session_replace_concurrent_reads_and_revoke() {
        let key = format!("acceptance-large-{}", uuid::Uuid::new_v4());
        let first = vec![0x53; 32 * 1024];
        let second = vec![0x54; 48 * 1024];
        let result = (|| {
            assert_eq!(NativeEntry.write(&key, &first), Err(Error::Unavailable));
            Native.write(&key, &first)?;
            assert_eq!(*Native.read(&key)?, first);
            Native.write(&key, &second)?;
            assert_eq!(*Native.read(&key)?, second);
            std::thread::scope(|scope| {
                for n in 0..4 {
                    let key = &key;
                    scope.spawn(move || {
                        for _ in 0..3 {
                            Native.write(key, &vec![n; 16000]).unwrap();
                            let value = Native.read(key).unwrap();
                            assert_eq!(value.len(), 16000);
                            assert!(value.iter().all(|byte| *byte == value[0]));
                        }
                    });
                }
            });
            Native.remove(&key)?;
            assert_eq!(Native.read(&key), Err(Error::Missing));
            Ok::<_, Error>(())
        })();
        let _ = Native.remove(&key);
        result.unwrap();
    }
}
