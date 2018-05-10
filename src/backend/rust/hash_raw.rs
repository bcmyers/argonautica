use failure;

use hasher::Hasher;
use output::HashRaw;

pub(crate) fn hash_raw_rust(hasher: &mut Hasher) -> Result<HashRaw, failure::Error> {
    let _ = hasher;
    unimplemented!()
}
