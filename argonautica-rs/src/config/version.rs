use std::str::FromStr;

use config::defaults::DEFAULT_VERSION;
use {Error, ErrorKind};

impl Default for Version {
    /// Returns [`Version::_0x13`](enum.Version.html#variant._0x13)
    fn default() -> Version {
        DEFAULT_VERSION
    }
}

impl FromStr for Version {
    ///
    type Err = Error;

    /// Performs the following mapping:
    /// * `"16"` => `Ok(Version::_0x10)`<br/>
    /// * `"19"` => `Ok(Version::_0x13)`<br/>
    /// * anything else => an error
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "16" => Ok(Version::_0x10),
            "19" => Ok(Version::_0x13),
            _ => {
                Err(Error::new(ErrorKind::VersionEncodeError).add_context(format!("String: {}", s)))
            }
        }
    }
}

/// Enum representing the various versions of the Argon2 algorithm (
/// [`0x10`](enum.Version.html#variant._0x10) and
/// [`0x13`](enum.Version.html#variant._0x13))
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Version {
    /// An outdated version of the Argon2 algorithm. Do <b><u>not</b></u> use this unless you have a specific reason to.
    _0x10 = 0x10,
    /// The default and latest version of the Argon2 algorithm (as of 5/18). Use this unless you have a specific reason not to.
    _0x13 = 0x13,
}

impl Version {
    /// Performs the following mapping:
    /// * `Version::_0x10` => `"16"`<br/>
    /// * `Version::_0x13` => `"19"`
    pub fn as_str(&self) -> &'static str {
        match *self {
            Version::_0x10 => "16",
            Version::_0x13 => "19",
        }
    }

    /// Performs the following mapping:
    /// * `16_u32` => `Ok(Version::_0x10)`<br/>
    /// * `19_u32` => `Ok(Version::_0x13)`<br/>
    /// * anything else => an error
    pub fn from_u32(x: u32) -> Result<Version, Error> {
        match x {
            16 => Ok(Version::_0x10),
            19 => Ok(Version::_0x13),
            _ => Err(Error::new(ErrorKind::VersionEncodeError).add_context(format!("Int: {}", x))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Version>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Version>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<Version>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<Version>();
    }
}
