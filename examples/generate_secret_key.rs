extern crate argonautica;
extern crate failure;

use argonautica::utils;

fn main() -> Result<(), failure::Error> {
    let base64_encoded_secret_key = utils::generate_random_base64_encoded_string(32)?;
    println!("{}", &base64_encoded_secret_key);
    Ok(())
}
