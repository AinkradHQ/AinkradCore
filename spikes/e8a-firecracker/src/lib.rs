//! Throwaway E8a-03 spike: length-prefixed protocol shared by guest init and host driver.
//! Frame = u32 BE length (type byte + payload) | type | payload. Max frame 1 MiB.
pub mod proto;
pub mod serve;
