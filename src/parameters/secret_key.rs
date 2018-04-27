use base64;
use failure;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SecretKey {
    Base64EncodedString(String),
    Bytes(Vec<u8>),
    String(String),
    None,
}

impl SecretKey {
    pub fn len(&self) -> Result<usize, failure::Error> {
        use self::SecretKey::*;
        match *self {
            Base64EncodedString(ref s) => {
                let bytes = base64::decode_config(s, base64::STANDARD)?;
                Ok(bytes.len())
            },
            Bytes(ref b) => Ok(b.len()),
            String(ref s) => Ok(s.as_bytes().len()),
            None => Ok(0),
        }
    }
    pub fn into_bytes(self) -> Result<Vec<u8>, failure::Error> {
        use self::SecretKey::*;
        match self {
            Base64EncodedString(s) => Ok(base64::decode_config(&s, base64::STANDARD)?),
            Bytes(b) => Ok(b),
            String(s) => Ok(s.into_bytes()),
            None => Ok(vec![]),
        }
    }
}
