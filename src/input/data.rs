pub(crate) trait Data {
    fn c_len(&self) -> u32;
    fn c_ptr(&self) -> *const u8;
}

impl<'a, T: Data> Data for Option<&'a T> {
    fn c_len(&self) -> u32 {
        match self {
            Some(ref data) => data.c_len(),
            None => 0,
        }
    }
    fn c_ptr(&self) -> *const u8 {
        match self {
            Some(ref data) => data.c_ptr(),
            None => ::std::ptr::null(),
        }
    }
}

pub(crate) trait DataMut {
    fn c_mut_ptr(&mut self) -> *mut u8;
}

impl<'a, T: DataMut> DataMut for Option<&'a mut T> {
    fn c_mut_ptr(&mut self) -> *mut u8 {
        match self {
            Some(ref mut data) => data.c_mut_ptr(),
            None => ::std::ptr::null_mut(),
        }
    }
}
