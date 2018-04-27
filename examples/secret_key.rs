extern crate a2;

use a2::utils;

fn main() {
    let base64_encoded_secret_key = utils::generate_secret_key(32).unwrap();
    println!("{}", &base64_encoded_secret_key);
}
