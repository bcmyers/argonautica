use data::{Data, DataPrivate};
use errors::DataError;
use {Error, ErrorKind};

impl<'a> From<&'a [u8]> for Password {
    fn from(bytes: &'a [u8]) -> Self {
        Password {
            bytes: bytes.to_vec(),
            constructed_from_borrow: true,
        }
    }
}

impl<'a> From<&'a str> for Password {
    fn from(s: &'a str) -> Self {
        let bytes = s.as_bytes().to_vec();
        Password {
            bytes,
            constructed_from_borrow: true,
        }
    }
}

impl From<Vec<u8>> for Password {
    fn from(bytes: Vec<u8>) -> Self {
        Password {
            bytes,
            constructed_from_borrow: false,
        }
    }
}

impl From<String> for Password {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        Password {
            bytes,
            constructed_from_borrow: false,
        }
    }
}

impl<'a> From<&'a Vec<u8>> for Password {
    fn from(bytes: &Vec<u8>) -> Self {
        Password {
            bytes: bytes.clone(),
            constructed_from_borrow: true,
        }
    }
}

impl<'a> From<&'a String> for Password {
    fn from(s: &String) -> Self {
        let bytes = s.as_bytes().to_vec();
        Password {
            bytes,
            constructed_from_borrow: true,
        }
    }
}

impl<'a> From<&'a Password> for Password {
    fn from(password: &Password) -> Self {
        let mut password = password.clone();
        password.constructed_from_borrow = true;
        password
    }
}

impl Data for Password {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Type-safe struct representing the raw bytes of your password
///
/// <i><u><b>Important note:</b></u>
///
/// If you construct a [`Password`](struct.Password.html) from a borrowed value (as opposed to
/// an owned value), you will <b>not</b> be able to use it with a [`Hasher`](../struct.Hasher.html)
/// or a [`Verifier`](../struct.Verifier.html) whose "password clearing" configuration is set to
/// `true`, which <b>is the default</b> (see [here](../index.html#configuration) for more details
/// on the "password clearing" configuration). This limitation (again, only when "password key
/// clearing" is set to `true`) is required because when you construct a
/// [`Password`](struct.Password.html) from a borrowed value, `a2` cannot guarantee that all
/// the underlying bytes of the [`Password`](struct.Password.html) will indeed be
/// erased after hashing and/or verifying, which is the whole point of the "password clearing"
/// feature.
///
/// Constructing a [`Password`](struct.Password.html) from an owned value (so that it can
/// be used by the default [`Hasher`](../struct.Hasher.html)
/// or [`Verifier`](../struct.Verifier.html)) is easy, just pass the
/// [`with_password`](../struct.Hasher.html#method.with_password) method on
/// [`Hasher`](../struct.Hasher.html) or [`Verifier`](../struct.Verifier.html) an owned value,
/// such as a `String` or a `Vec<u8>`, instead of a borrowed value (such as a `&str` or a `&[u8]`).
/// Alternatively, you can use a [`Hasher`](../struct.Hasher.html) or
/// a [`Verifier`](../struct.Verifier.html) with [`Password`](struct.Password.html)s constructed
/// from borrowed values if you set their "password clearing" configuration to `false` using the
/// [`configure_password_clearing`](../struct.Hasher.html#method.configure_password_clearing)
/// method</i>
///
/// <i><u>Example using an <b>owned</b> password whose underlying bytes will be completely erased
/// after hashing:</i></u>
/// ```
/// extern crate a2;
/// extern crate failure;
///
/// fn main() -> Result<(), failure::Error> {
///     let password = "P@ssw0rd".to_string();
///     let mut hasher = a2::Hasher::default();
///     let hash = hasher
///         .with_password(password)
///         .with_secret_key("secret")
///         .hash()?;
///     // 👉 Here the underlying bytes of `password` have been completely erased.
///     // 👉 Not only is `password` inaccessable because of Rust's type system,
///     // 👉 it's underyling bytes have been completely zeroed out as well
///     println!("{}", &hash);
///     Ok(())
/// }
/// ```
/// <u><i>Example using a <b>borrowed</b> password whose underlying bytes will remain
/// accessable after hashing:</u></i>
/// ```
/// extern crate a2;
/// extern crate failure;
///
/// fn main() -> Result<(), failure::Error> {
///     let password = "P@ssword";
///     let mut hasher = a2::Hasher::default();
///     let hash = hasher
///         .configure_password_clearing(false)
///         .with_password(password)
///                         // 👆Ok to pass a borrowed value since "password clearing" is `false`
///         .with_secret_key("secret")
///         .hash()?;
///     // 👉 Here `password` remains accessable, unlike in the first example above
///     println!("{}", password);
///     println!("{}", &hash);
///     Ok(())
/// }
/// ```

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Password {
    bytes: Vec<u8>,
    constructed_from_borrow: bool,
}

impl Password {
    pub(crate) fn constructed_from_borrow(&self) -> bool {
        self.constructed_from_borrow
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.bytes.is_empty() {
            return Err(ErrorKind::DataError(DataError::PasswordTooShortError).into());
        }
        if self.bytes.len() >= ::std::u32::MAX as usize {
            return Err(
                Error::new(ErrorKind::DataError(DataError::PasswordTooLongError))
                    .add_context(format!("Length: {}", self.bytes.len())),
            );
        }
        Ok(())
    }
}

impl DataPrivate for Password {
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constructed_from_borrow_password() {
        let password: Password = vec![0u8].into();
        assert!(!password.constructed_from_borrow());

        let password: Password = "string".to_string().into();
        assert!(!password.constructed_from_borrow());

        let password: Password = "str".into();
        assert!(password.constructed_from_borrow());

        let password: Password = (&[0u8][..]).into();
        assert!(password.constructed_from_borrow());

        let password: Password = vec![0u8].into();
        let password: Password = (&password).into();
        assert!(password.constructed_from_borrow());
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Password>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Password>();
    }
}
