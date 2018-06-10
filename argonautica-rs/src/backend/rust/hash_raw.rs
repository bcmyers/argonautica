#![allow(dead_code)]

use hasher::Hasher;
use output::HashRaw;
use Error;

pub(crate) fn hash_raw_rust(hasher: &mut Hasher) -> Result<HashRaw, Error> {
    let _ = hasher;
    unimplemented!()
}
