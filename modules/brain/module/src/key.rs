//! The one brain key (Q-6, Q-7, E0-3): 32 random bytes kept as a normal Core sealed secret
//! `brain.key`, so the master key's rotation re-seals it. The raw key lives only in this process's
//! memory (zeroised on drop); it is never logged or audited.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::App;
use ainkrad_core_server::module::Zeroizing;
use ainkrad_core_server::store::secrets::{self, Error, NewValue};

pub const NAME: &str = "brain.key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Ok,
    /// `secrets.mode` 0: the brain is locked, fail closed (Q-48).
    LockedMode0,
    /// The broker is on and no key was made yet (the first import makes it).
    Missing,
    /// This Core holds no master key.
    Unavailable,
}

impl KeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::LockedMode0 => "locked_mode0",
            Self::Missing => "missing",
            Self::Unavailable => "unavailable",
        }
    }
}

pub async fn state(app: &App) -> KeyState {
    if app.secrets.is_none() {
        return KeyState::Unavailable;
    }
    if secrets::require_enabled(&app.pool).await.is_err() {
        return KeyState::LockedMode0;
    }
    match secrets::list(&app.pool).await {
        Ok(all) if all.iter().any(|m| m.name == NAME) => KeyState::Ok,
        _ => KeyState::Missing,
    }
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Opens the key, creating it on first use. Errors carry a stable code, never key material.
/// `owner` is the device that asks; without one the key is only opened, never made.
pub async fn load_or_create(
    app: &App,
    owner: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let sealer = app.secrets.as_deref().ok_or(KeyError::Unavailable)?;
    for _ in 0..2 {
        match secrets::open_for_module(&app.pool, sealer, "brain", NAME, "import").await {
            Ok(v) => return from_hex(&v).map(Zeroizing::new).ok_or(KeyError::Corrupt),
            Err(Error::Refused {
                code: "secrets_disabled",
                ..
            }) => return Err(KeyError::LockedMode0),
            Err(Error::Refused {
                code: "not_found", ..
            }) => {}
            Err(e) => {
                tracing::error!(error = %e, "the brain key could not be opened");
                return Err(KeyError::Unavailable);
            }
        }
        let Some(owner) = owner else {
            return Err(KeyError::Missing);
        };
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *raw).map_err(|_| KeyError::Unavailable)?;
        let hex = Zeroizing::new(raw.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let made = secrets::create(
            &app.pool,
            sealer,
            NAME,
            &NewValue {
                value: &hex,
                runners: None,
                delivery: None,
            },
            owner,
            AuditActor::System,
            &app.clock.now(),
        )
        .await;
        match made {
            Ok(_) => return Ok(raw),
            // Another request made it first: open theirs.
            Err(Error::Refused {
                code: "conflict", ..
            }) => {}
            Err(Error::Refused {
                code: "secrets_disabled",
                ..
            }) => return Err(KeyError::LockedMode0),
            Err(e) => {
                tracing::error!(error = %e, "the brain key could not be created");
                return Err(KeyError::Unavailable);
            }
        }
    }
    Err(KeyError::Unavailable)
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    LockedMode0,
    Unavailable,
    Corrupt,
    /// No key yet and nobody asked to make one.
    Missing,
}
