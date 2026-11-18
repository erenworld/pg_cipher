/*-------------------------------------------------------------------------
 *
 * datum.rs
 *        Generic encrypted value shared by all pg_cipher types.
 *
 *-------------------------------------------------------------------------
 */

use pgrx::prelude::*;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::global::Global;
use chacha20poly1305::aead::{Aead, AeadCore, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

#[derive(PostgresType, Serialize, Deserialize, Debug, Eq, PartialEq, Ord, Hash, PartialOrd)]
pub struct TceDatum {
    pub nonce: Vec<u8>,
    pub cipher_vec: Vec<u8>,
}

impl TceDatum {
    /* Encrypt plain bytes into a new TceDatum with  */
    pub fn from_plain_bytes(plain_bytes: Vec<u8>) -> Result<Self> {
        let cipher = &Global::get()?.cipher;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher_vec = cipher
        .encrypt(&nonce, plain_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("pg_cipher: encryption failed: {e}"))?;

        Ok(Self {
            nonce: nonce.to_vec(),
            cipher_vec,
        })
    }

    pub fn to_plain_bytes(&self) -> Result<Vec<u8>> {
        let cipher = &Global::get()?.cipher;
        let nonce = Nonce::from_slice(&self.nonce);
    
        let plain_bytes = cipher
            .decrypt(nonce, self.cipher_vec.as_slice())
            .map_err(|e| anyhow::anyhow!("pg_cipher: decryption failed: {e}"))?;

        Ok(plain_bytes)
    }

    /* Encrypted bytes as TCE:b1:b2:... without decrypting */
    fn raw(&self) -> String {
        format!(
            "TCE:{}",
            self.cipher_vec
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(":")
        )
    }
}