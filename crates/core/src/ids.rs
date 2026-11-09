//! Id newtypes and closed text enums, the building blocks of every other primitive.

use std::fmt;

macro_rules! id {
    ($($name:ident),*) => {$(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub i64);
    )*};
}
pub(crate) use id;

id!(UserId, DeviceKeyId);

/// A string that is not one of an enum's known values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVariant(pub String);

impl fmt::Display for UnknownVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown variant `{}`", self.0)
    }
}

impl std::error::Error for UnknownVariant {}

/// A closed enum with a stable snake_case text form (used as the storage value).
macro_rules! text_enum {
    ($name:ident { $($variant:ident => $text:literal),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),* }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),* }
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::ids::UnknownVariant;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($text => Ok(Self::$variant),)*
                    other => Err($crate::ids::UnknownVariant(other.to_owned())),
                }
            }
        }
    };
}
pub(crate) use text_enum;
