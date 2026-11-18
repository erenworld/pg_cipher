use crate::global::Global;
use crate::pg_type::datum::TceDatum;
use crate::Result;

use chacha20poly1305::aead::Aead;
use pgrx::prelude::*;
use pgrx::{InOutFuncs, StringInfo};
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
pub struct TceText(TceDatum);

impl TceText {
    /* Decrypt the value and decode it as UTF-8 */
    fn to_string(&self) -> Result<String> {
        let plain_bytes = self.0.to_plain_bytes()?;
        Ok(String::from_utf8(plain_bytes)?)
    }
}

impl InOutFuncs for TceText {
    fn input(input: &core::ffi::CStr) -> Self {
        let plain_bytes = input.to_bytes().to_vec();
        let datum = match TceDatum::from_plain_bytes(plain_bytes) {
            Ok(d) => d,
            Err(e) => pgrx::error!("{e}"),
        };

        TceText(datum)
    }

    fn output(&self, buffer: &mut StringInfo) {
        match self.to_string() {
            Ok(val) => buffer.push_str(&val),
            Err(_) => buffer.push_str("[ENCRYPTED]"),
        }
    }
}
