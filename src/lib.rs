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

/*
 * fetch_key_from_local_file
 *        Load the encryption key from a file on the database server.
 *
 * Returns true if the key was loaded, false if a key was already loaded in
 * this session, and NULL if the file cannot be read.
 */
#[pg_extern]
fn fetch_key_from_local_file(file_path: &str) -> Option<bool> {
    let g = Global::from_file(file_path).ok()?;
    Some(Global::set(g))
}

/*
 * fetch_key_from_remote_file
 *        Load the encryption key from an HTTP(S) URL.
 *
 * Same return values as fetch_key_from_local_file.
 */
#[pg_extern]
fn fetch_key_from_remote_file(url: &str) -> Option<bool> {
    let g = Global::from_url(url).ok()?;
    Some(Global::set(g))
}

/*
 * TceText
 *        A text value stored encrypted on disk.
 *
 * Only the ciphertext is stored.  Since encryption is deterministic (fixed
 * nonce), two equal plaintexts give equal ciphertexts: equality, hashing
 * and btree indexes work on the ciphertext directly.
 *
 * Note that ordering follows the ciphertext bytes, not the plaintext.
 */
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
    /*
     * input
     *        Encrypt the text typed by the user (e.g. 'alice'::tcetext).
     *
     * Raises an error if no key is loaded in this session.
     */
    fn input(input: &core::ffi::CStr) -> Self {
        let g = Global::get();
        let ciphertext = g
            .cipher
            .encrypt(&g.nonce, input.to_bytes())
            .expect("pg_cipher: encryption failed");
        TceText { ciphertext }
    }

    /*
     * output
     *       Decrypt the value for display
     *
     * Without a key, the raw ciphertext bytes are printed instead of raising an error, so that SELECT * still works in a session with no key.
     * 
     * Raises an error if decryption fails (wrong or corrupted key)
     */
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

/*
* raw
*       Return the ciphertext of a TCETEXT value, without decrypting it.
* 
* Works without a key. Useful to check what is actually stored.
*/
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
