extern crate a2;
extern crate failure;

use a2::utils;

fn main() {
    run().unwrap();
}

fn run() -> Result<(), failure::Error> {
    let base64_encoded_secret_key = utils::generate_random_base64_encoded_string(32)?;
    println!("{}", &base64_encoded_secret_key);
    Ok(())
}
