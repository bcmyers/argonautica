use {Error, ErrorKind};

impl From<Vec<u8>> for AdditionalData {
    fn from(bytes: Vec<u8>) -> AdditionalData {
        AdditionalData(bytes)
    }
}

impl From<String> for AdditionalData {
    fn from(s: String) -> AdditionalData {
        AdditionalData(s.into_bytes())
    }
}

impl<'a> From<&'a [u8]> for AdditionalData {
    fn from(bytes: &[u8]) -> AdditionalData {
        AdditionalData(bytes.to_vec())
    }
}

impl<'a> From<&'a str> for AdditionalData {
    fn from(s: &str) -> AdditionalData {
        AdditionalData(s.as_bytes().to_vec())
    }
}

impl<'a> From<&'a Vec<u8>> for AdditionalData {
    fn from(bytes: &Vec<u8>) -> AdditionalData {
        AdditionalData(bytes.clone())
    }
}

impl<'a> From<&'a String> for AdditionalData {
    fn from(s: &String) -> AdditionalData {
        AdditionalData(s.clone().into_bytes())
    }
}

impl<'a> From<&'a AdditionalData> for AdditionalData {
    fn from(additional_data: &AdditionalData) -> AdditionalData {
        additional_data.clone()
    }
}

/// Type-safe struct representing the raw bytes of your additional data (if any)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AdditionalData(Vec<u8>);

impl AdditionalData {
    /// Read-only access to the underlying byte buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Read-only acccess to the underlying byte buffer's length
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Read-only access to the underlying byte buffer as a `&str` if its bytes are valid utf-8
    pub fn to_str(&self) -> Result<&str, Error> {
        let s = ::std::str::from_utf8(self.as_bytes()).map_err(|_| {
            Error::new(ErrorKind::Utf8EncodeError)
                .add_context(format!("Bytes: {:?}", self.as_bytes()))
        })?;
        Ok(s)
    }
}

impl AdditionalData {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.len() >= ::std::u32::MAX as usize {
            return Err(Error::new(ErrorKind::AdditionalDataTooLongError)
                .add_context(format!("Length: {}", self.0.len())));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AdditionalData>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AdditionalData>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize() {
        use serde;
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<AdditionalData>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize() {
        use serde;
        fn assert_deserialize<'de, T: serde::Deserialize<'de>>() {}
        assert_deserialize::<AdditionalData>();
    }
}
