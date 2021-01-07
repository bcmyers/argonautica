#[derive(Debug, Eq, PartialEq, Hash)]
#[allow(missing_docs)]
pub enum Container<'a> {
    Borrowed(&'a [u8]),
    BorrowedMut(&'a mut [u8]),
    Owned(Vec<u8>),
}

impl<'a> Container<'a> {
    #[allow(missing_docs)]
    pub fn to_owned(&self) -> Container<'static> {
        match self {
            Container::Borrowed(ref bytes) => Container::Owned(bytes.to_vec()),
            Container::BorrowedMut(ref bytes) => Container::Owned(bytes.to_vec()),
            Container::Owned(ref bytes) => Container::Owned(bytes.to_vec()),
        }
    }
}
