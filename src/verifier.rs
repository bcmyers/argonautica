use std::ffi::CString;
use std::os::raw::c_char;

use failure;
use scopeguard;

use config::variant::Variant;
use data::additional_data::AdditionalData;
use data::password::Password;
use data::read::ReadPrivate;
use data::secret_key::SecretKey;
use ffi;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Verifier {
    additional_data: AdditionalData,
    hash: Hash,
    password: Password,
    secret_key: SecretKey,
}

impl Default for Verifier {
    fn default() -> Verifier {
        Verifier::new()
    }
}

// TODO: Getters
impl Verifier {
    pub fn new() -> Verifier {
        Verifier {
            additional_data: AdditionalData::none(),
            hash: Hash::none(),
            password: Password::none(),
            secret_key: SecretKey::none(),
        }
    }

    pub fn with_additional_data<AD: Into<AdditionalData>>(&mut self, additional_data: AD) -> &mut Verifier {
        self.additional_data = additional_data.into();
        self
    }

    pub fn with_hash(&mut self, hash: &str) -> &mut Verifier {
        self.hash = Hash::Encoded(hash.to_string());
        self
    }

    pub fn with_hash_raw(&mut self, hash_raw: &[u8]) -> &mut Verifier {
        self.hash = Hash::Raw(hash_raw.to_vec());
        self
    }

    pub fn with_password<P: Into<Password>>(&mut self, password: P) -> &mut Verifier {
        self.password = password.into();
        self
    }

    pub fn with_secret_key<SK: Into<SecretKey>>(&mut self, secret_key: SK) -> &mut Verifier {
        self.secret_key = secret_key.into();
        self
    }

    pub fn verify(&mut self) -> Result<bool, failure::Error> {
        let mut instance = scopeguard::guard(self, |instance| {
            instance.hash = Hash::none();
            instance.password = Password::none();
        });
        match instance.hash.clone() {
            Hash::Encoded(ref s) => Ok(instance._verify(s)?),
            Hash::Raw(ref bytes) => Ok(instance._verify_raw(bytes)?),
        }
    }

    pub fn _verify(&mut self, hash: &str)  -> Result<bool, failure::Error> {
        let hash_length = hash.as_bytes().len();
        let mut buffer = vec![0u8; hash_length];
        let mut salt = vec![0u8; hash_length];

        let mut context = ffi::Argon2_Context {
            out: buffer.as_mut_ptr(),
            outlen: buffer.len() as u32,
            pwd: ::std::ptr::null_mut(),
            pwdlen: 0,
            salt: salt.as_mut_ptr(),
            saltlen: salt.len() as u32,
            secret: ::std::ptr::null_mut(),
            secretlen: 0,
            ad: ::std::ptr::null_mut(),
            adlen: 0,
            t_cost: 0,
            m_cost: 0,
            lanes: 0,
            threads: 0,
            version: 0,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };

        let context_ptr = &mut context as *mut ffi::argon2_context;
        let hash_cstring = CString::new(hash)?;
        let hash_cstring_ptr = hash_cstring.as_ptr();
        let variant = parse_variant(&hash)?;
        let err = unsafe { ffi::decode_string(context_ptr, hash_cstring_ptr, variant as u32) };
        if err != 0 {
            bail!("Argon2 error: {}", err); // Todo
        }

        let desired_result_ptr = context.out as *const c_char;

        let mut buffer = vec![0u8; context.outlen as usize];
        context.ad = self.additional_data.as_mut_ptr();
        context.adlen = self.additional_data.len() as u32;
        context.out = buffer.as_mut_ptr();
        context.outlen = buffer.len() as u32;
        context.pwd = self.password.as_mut_ptr();
        context.pwdlen = self.password.len() as u32;
        context.secret = self.secret_key.as_mut_ptr();
        context.secretlen = self.secret_key.len() as u32;

        let context_ptr = &mut context as *mut ffi::argon2_context;
        let err =
            unsafe { ffi::argon2_verify_ctx(context_ptr, desired_result_ptr, variant as u32) };
        let is_valid = if err == 0 {
            true
        } else if err == ffi::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH {
            false
        } else {
            bail!("Argon2 error: {}", err); // Todo
        };
        Ok(is_valid)
    }

    // TODO
    pub fn _verify_raw(&mut self, hash: &[u8]) -> Result<bool, failure::Error> {
        let _ = hash;
        Ok(true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum Hash {
    Raw(Vec<u8>),
    Encoded(String),
}

impl Hash {
    fn none() -> Hash {
        Hash::Raw(vec![])
    }
}

fn parse_variant(encoded: &str) -> Result<Variant, failure::Error> {
    let first_letter = match encoded.chars().nth(7) {
        Some(c) => c,
        None => bail!("invalid hash format"),
    };
    let second_letter = match encoded.chars().nth(8) {
        Some(c) => c,
        None => bail!("invalid hash format"),
    };
    let variant = if first_letter == 'i' && second_letter == 'd' {
        Variant::Argon2id
    } else {
        match first_letter {
            'i' => Variant::Argon2i,
            'd' => Variant::Argon2d,
            _ => bail!("invalid hash format"),
        }
    };
    Ok(variant)
}
