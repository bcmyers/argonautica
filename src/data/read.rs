use base64;
use failure;

pub trait Read {
    fn as_bytes(&self) -> &[u8];

    fn as_str(&self) -> Result<&str, failure::Error> {
        Ok(::std::str::from_utf8(self.as_bytes())?)
    }

    fn to_base64_encoded_string(&self) -> String {
        base64::encode_config(self.as_bytes(), base64::STANDARD)
    }
}

pub(crate) trait ReadPrivate: Read {
    fn as_mut_bytes(&mut self) -> &mut [u8];
    fn validate(&self, extra: Option<bool>) -> Result<(), failure::Error>;

    fn as_mut_ptr(&mut self) -> *mut u8 {
        let ptr: *mut u8 = match self.as_bytes().len() {
            0 => ::std::ptr::null_mut(),
            _ => self.as_mut_bytes().as_mut_ptr(),
        };
        ptr
    }
    fn len(&self) -> u32 {
        self.as_bytes().len() as u32
    }
}
