#![allow(dead_code)]

use error::Error;
use hasher::Hasher;
use output::HashRaw;

pub(crate) fn hash_raw_rust(hasher: &mut Hasher) -> Result<HashRaw, Error> {
    let _ = hasher;
    unimplemented!()
}
