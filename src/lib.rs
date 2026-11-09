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
use pgrx::prelude::*;

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


#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;
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
