/*-------------------------------------------------------------------------
 *
 * global.rs
 *        Per-backend storage of the encryption key.
 *
 * The key is loaded once per session (see fetch_key_from_local_file and
 * fetch_key_from_remote_file) and kept in memory for the lifetime of the
 * backend process.
 *
 *-------------------------------------------------------------------------
 */

use chacha20poly1305::{ChaCha20Poly1305, aead::KeyInit};
use once_cell::sync::OnceCell;

use crate::Result;
use crate::actor::TceError;

static GLOBAL: OnceCell<Global> = OnceCell::new();

pub struct Global {
    pub cipher: ChaCha20Poly1305, /* expanded secret key */
}

impl Global {
    pub fn get() -> Result<&'static Global> {
        Ok(GLOBAL.get().ok_or(TceError::KeyNotLoaded)?)
    }

    pub fn set(g: Global) -> bool {
        GLOBAL.set(g).is_ok()
    }

    /*
     * TODO: load the nonce from a GUC instead of hardcoding it.
     */
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        Global {
            cipher: ChaCha20Poly1305::new_from_slice(bytes)
                .expect("pg_cipher: key must be 32 bytes"),
        }
    }

    pub fn new(content: &str) -> Self {
        let hex = content.trim().replace("0x", "").replace(' ', "");

        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("pg_cipher: invalid hex in key"))
            .collect();

        Global::new_from_bytes(&bytes)
    }

    pub fn from_file(file_path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(file_path)?;
        Ok(Global::new(&content))
    }

    pub fn from_url(url: &str) -> Result<Self> {
        let mut response = ureq::get(url).call()?;
        let content = response.body_mut().read_to_string()?;
        Ok(Global::new(&content))
    }
}
