/*-------------------------------------------------------------------------
 *
 * lib.rs
 *        Entry point of the pg_cipher extension.
 *
 * Exposes the SQL functions to load the encryption key, and the TCETEXT
 * type, which is encrypted on input and decrypted on output.
 *
 *-------------------------------------------------------------------------
 */

mod global;

use crate::global::Global;
use chacha20poly1305::aead::Aead;
use pgrx::prelude::*;
use pgrx::{InOutFuncs, StringInfo};
use serde::{Deserialize, Serialize};

::pgrx::pg_module_magic!(name, version);

#[pg_extern]
fn fetch_key_from_local_file(file_path: &str) -> Option<bool> {
    let g = Global::from_file(file_path).ok()?;
    Some(Global::set(g))
}

#[pg_extern]
fn fetch_key_from_remote_file(url: &str) -> Option<bool> {
    let g = Global::from_url(url).ok()?;
    Some(Global::set(g))
}

#[derive(
    PostgresType,
    Serialize,
    Deserialize,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    PostgresEq,
    PostgresOrd,
    PostgresHash,
)]
#[inoutfuncs]
pub struct TceText {
    ciphertext: Vec<u8>,
}

impl InOutFuncs for TceText {
    fn input(input: &core::ffi::CStr) -> Self {
        let g = Global::get();
        let ciphertext = g
            .cipher
            .encrypt(&g.nonce, input.to_bytes())
            .expect("pg_cipher: encryption failed");
        TceText { ciphertext }
    }

    fn output(&self, buffer: &mut StringInfo) {
        if Global::is_none() {
            buffer.push_str(&format!("{:?}", self.ciphertext));
            return;
        }

        let g = Global::get();
        let plaintext = g
                .cipher
                .decrypt(&g.nonce, self.ciphertext.as_slice())
                .expect("pg_cipher: decryption failed");

            buffer.push_str(std::str::from_utf8(&plaintext).expect("pg_cipher: invalid UTF-8"));
    }
}

#[pg_extern]
fn raw(val: TceText) -> Vec<u8> {
    val.ciphertext
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use crate::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    #[pg_test]
    fn test_fetch_key_from_local_file() {
        let path = fixtures_dir().join("untrusted_chacha_key.txt");
        assert_eq!(fetch_key_from_local_file(path.to_str().unwrap()), Some(true));
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
