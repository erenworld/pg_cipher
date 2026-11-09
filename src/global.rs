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

use std::sync::Once;

use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305, Nonce};
use once_cell::sync::OnceCell;

static GLOBAL: OnceCell<Global> = OnceCell::new();

/*
 * Global
 *        Everything needed to encrypt or decrypt a value.
 *
 * cipher holds the key, already expanded for ChaCha20-Poly1305.
 * nonce is a fixed 12-byte value: this makes encryption deterministic,
 * which allows equality, indexes and ORDER BY on encrypted columns.
 *
 */
pub struct Global {
    pub cipher: ChaCha20Poly1305,
    pub nonce: Nonce,
}