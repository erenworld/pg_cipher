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
mod pg_type;
mod actor;

use crate::global::Global;
use pgrx::prelude::*;

::pgrx::pg_module_magic!(name, version);

type Result<T> = anyhow::Result<T>;

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
