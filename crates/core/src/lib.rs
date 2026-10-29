//! Platform primitives: ids, the audit log's types, device keys and the settings registry.
//! No I/O, and no module's domain: a module brings its own types.

pub mod audit;
pub mod device;
pub mod ids;
pub mod settings;
