/*-------------------------------------------------------------------------
 *
 * error.rs
 *        Errors raised by pg_cipher.
 *
 *-------------------------------------------------------------------------
 */

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TceError {
    #[error("pg_cipher: secret is not loaed")]
    KeyNotLoaded,
}
