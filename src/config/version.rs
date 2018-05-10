use std::str::FromStr;

use failure;

use config::defaults::DEFAULT_VERSION;

impl Default for Version {
    /// `Version::_0x13`
    fn default() -> Version {
        DEFAULT_VERSION
    }
}

impl FromStr for Version {
    ///
    type Err = failure::Error;

    /// `"16"` => `Ok(Version::_0x10)`<br/>
    /// `"19"` => `Ok(Version::_0x13)`<br/>
    /// anything else   => error
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "16" => Ok(Version::_0x10),
            "19" => Ok(Version::_0x13),
            _ => bail!("TODO: failed to parse Version from &str"),
        }
    }
}

/// Enum repressenting the choice between versions of the Argon2 algorithm (`0x10` and `0x13`)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Version {
    /// An outdated version of the Argon2 algorithm. Do <b><u>not</b></u> use this unless you have a specific reason to.
    _0x10 = 0x10,
    /// The default and latest version of the Argon2 algorithm (as of 5/18). Use this unless you have a specific reason not to.
    _0x13 = 0x13,
}

impl Version {
    /// `Version::_0x10` => `"16"`<br/>
    /// `Version::_0x13` => `"19"`
    pub fn as_str(&self) -> &'static str {
        match *self {
            Version::_0x10 => "16",
            Version::_0x13 => "19",
        }
    }

    /// `16_u32` => `Ok(Version::_0x10)`<br/>
    /// `19_u32` => `Ok(Version::_0x13)`<br/>
    /// anything else => error
    pub fn from_u32(x: u32) -> Result<Version, failure::Error> {
        match x {
            16 => Ok(Version::_0x10),
            19 => Ok(Version::_0x13),
            _ => bail!("TODO"),
        }
    }
}
