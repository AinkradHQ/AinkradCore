//! Decoding remote bytes without trusting them. yrs's own `Any` decoder recurses once per nesting level and reserves
//! collections at the size the bytes claim, so a deep or lying value can exhaust the stack (an abort) or memory. Every
//! `Any` in an update is read through `Guarded::read_any` instead: depth-capped, and no collection longer than the
//! bytes left. Only `Any` content reaches the document this way, so later encodes and drops stay shallow too.
//!
//! Also refused: a client listed twice in one update. yrs merges the two block lists, which then overlap, and its
//! integration frees a block that is still referenced (a heap use-after-free found by the `apply` fuzz target, seed
//! `fuzz/regressions/duplicate-client-uaf`). An honest update lists each client once.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use yrs::encoding::read::{Error as ReadError, Read};
use yrs::updates::decoder::{Decode, Decoder, DecoderV1};
use yrs::{Any, ClientID, ID, Number, Update};

use crate::{Error, MAX_JSON_DEPTH};

/// The yrs decoder, the input length, the clients whose blocks were read so far, and every block id the update
/// refers to (origins and parents: what it builds on).
struct Guarded<'a>(DecoderV1<'a>, usize, HashSet<u64>, Vec<ID>);

impl Guarded<'_> {
    fn any(&mut self, depth: usize) -> Result<Any, ReadError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ReadError::UnexpectedValue);
        }
        Ok(match self.0.read_u8()? {
            127 => Any::Undefined,
            126 => Any::Null,
            125 => Any::Number(Number::Int(self.0.read_var::<i64>()?)),
            124 => Any::Number(Number::Float(self.0.read_f32()? as f64)),
            123 => Any::Number(Number::Float(self.0.read_f64()?)),
            122 => Any::Number(Number::Int(self.0.read_i64()?)),
            121 => Any::Bool(false),
            120 => Any::Bool(true),
            119 => Any::String(Arc::from(self.0.read_string()?)),
            118 => {
                let n = self.len()?;
                let mut m = HashMap::new();
                for _ in 0..n {
                    let k = self.0.read_string()?.to_owned();
                    m.insert(k, self.any(depth + 1)?);
                }
                Any::Map(Arc::new(m))
            }
            117 => {
                let n = self.len()?;
                let mut v = Vec::new();
                for _ in 0..n {
                    v.push(self.any(depth + 1)?);
                }
                Any::Array(v.into())
            }
            116 => Any::Buffer(Arc::from(self.0.read_buf()?)),
            _ => return Err(ReadError::UnexpectedValue),
        })
    }

    /// A collection length: each element takes at least one byte, so more than the input holds is a lie.
    fn len(&mut self) -> Result<usize, ReadError> {
        let n: usize = self.0.read_var()?;
        if n > self.1 {
            return Err(ReadError::UnexpectedValue);
        }
        Ok(n)
    }
}

impl Read for Guarded<'_> {
    fn read_exact(&mut self, len: usize) -> Result<&[u8], ReadError> {
        self.0.read_exact(len)
    }
    fn read_u8(&mut self) -> Result<u8, ReadError> {
        self.0.read_u8()
    }
}

impl Decoder for Guarded<'_> {
    fn reset_ds_cur_val(&mut self) {
        self.0.reset_ds_cur_val()
    }
    fn read_ds_clock(&mut self) -> Result<u32, ReadError> {
        self.0.read_ds_clock()
    }
    fn read_ds_len(&mut self) -> Result<u32, ReadError> {
        self.0.read_ds_len()
    }
    fn read_left_id(&mut self) -> Result<ID, ReadError> {
        let id = self.0.read_left_id()?;
        self.3.push(id);
        Ok(id)
    }
    fn read_right_id(&mut self) -> Result<ID, ReadError> {
        let id = self.0.read_right_id()?;
        self.3.push(id);
        Ok(id)
    }
    /// Only the block section reads clients this way (the delete set reads plain varints).
    fn read_client(&mut self) -> Result<ClientID, ReadError> {
        let c = self.0.read_client()?;
        if !self.2.insert(c.get()) {
            return Err(ReadError::UnexpectedValue);
        }
        Ok(c)
    }
    fn read_info(&mut self) -> Result<u8, ReadError> {
        self.0.read_info()
    }
    fn read_parent_info(&mut self) -> Result<bool, ReadError> {
        self.0.read_parent_info()
    }
    fn read_type_ref(&mut self) -> Result<u8, ReadError> {
        self.0.read_type_ref()
    }
    fn read_len(&mut self) -> Result<u32, ReadError> {
        self.0.read_len()
    }
    fn read_any(&mut self) -> Result<Any, ReadError> {
        self.any(0)
    }
    /// JSON content (embeds, formats) goes through serde_json, which stops at 128 levels.
    fn read_json(&mut self) -> Result<Any, ReadError> {
        self.0.read_json()
    }
    fn read_key(&mut self) -> Result<Arc<str>, ReadError> {
        self.0.read_key()
    }
    fn read_to_end(&mut self) -> Result<&[u8], ReadError> {
        self.0.read_to_end()
    }
}

/// yrs decoders also panic on some malformed input (e.g. a client id over 53 bits). Decoding touches no shared
/// state, so a panic there is caught and reported as malformed bytes.
pub(crate) fn caught<T, E: std::fmt::Display>(
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, Error> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Error::Malformed(e.to_string())),
        Err(_) => Err(Error::Malformed("undecodable".into())),
    }
}

/// A v1 update, with every `Any` in it depth- and length-checked, and the ids it refers to.
pub(crate) fn update(bytes: &[u8]) -> Result<(Update, Vec<ID>), Error> {
    let mut g = Guarded(DecoderV1::from(bytes), bytes.len(), HashSet::new(), vec![]);
    let u = caught(|| Update::decode(&mut g))?;
    Ok((u, g.3))
}
