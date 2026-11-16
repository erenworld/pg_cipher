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

use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305, Nonce};
use once_cell::sync::OnceCell;

static GLOBAL: OnceCell<Global> = OnceCell::new();

pub struct Global {
    pub cipher: ChaCha20Poly1305, /* expanded secret key */
    pub nonce: Nonce,             /* 12 bytes, same for every value */
}

impl Global {
    pub fn get() -> &'static Global {
        GLOBAL.get().expect("pg_cipher: secret key is not loaded")
    }

    pub fn is_none() -> bool {
        GLOBAL.get().is_none()
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
            nonce: Nonce::from([
                0xa7, 0xb8, 0xc9, 0xd0, 0xe1, 0xf2, 0x03, 0x45, 0x67, 0x89, 0x0a, 0xbc,
            ]),
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

    pub fn from_file(file_path: &str) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(file_path)?;
        Ok(Global::new(&content))
    }

    pub fn from_url(url: &str) -> Result<Self, ureq::Error> {
        let mut response = ureq::get(url).call()?;
        let content = response.body_mut().read_to_string()?;
        Ok(Global::new(&content))
    }
}
