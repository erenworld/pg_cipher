use crate::global::Global;
use chacha20poly1305::aead::Aead;
use pgrx::{InOutFuncs, StringInfo};
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};

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
        let g = match Global::get() {
            Ok(g) => g,
            Err(e) => pgrx::error!("{e}"),
        };

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

        let g = match Global::get() {
            Ok(g) => g,
            Err(e) => pgrx::error!("{e}"),
        };
        
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